package hostedworker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Parallax-Web-Services/nucleus/inference"
)

type downloader struct{ client *http.Client }

var revisionHash = regexp.MustCompile("^[0-9a-f]{40}$")
var downloadHosts = map[string]bool{
	"huggingface.co": true, "cdn-lfs.huggingface.co": true, "cdn-lfs.hf.co": true,
	"cdn-lfs-us-1.hf.co": true, "cdn-lfs-eu-1.hf.co": true, "cas-bridge.xethub.hf.co": true,
}

func approvedDownloadURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil && u.Opaque == "" && u.Fragment == "" && u.RawPath == "" && (u.Port() == "" || u.Port() == "443") && downloadHosts[strings.ToLower(u.Hostname())]
}

// Special-use addresses are rejected even when Go calls them global unicast
// (notably CGNAT, benchmark/documentation networks, and transition mechanisms).
var prohibitedDownloadPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicDownloadIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range prohibitedDownloadPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func newDownloader() *downloader {
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 20 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" || !downloadHosts[strings.ToLower(host)] {
				return nil, errors.New("model download host is not permitted")
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(addresses) == 0 {
				return nil, errors.New("cannot resolve approved model host")
			}
			for _, ip := range addresses {
				if !publicDownloadIP(ip.IP) {
					return nil, errors.New("model host resolved to a prohibited network")
				}
			}
			dialer := net.Dialer{Timeout: 10 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
		},
	}
	return &downloader{client: &http.Client{Transport: transport, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > 4 || !approvedDownloadURL(request.URL) {
			return errors.New("model redirect is not permitted")
		}
		request.Header.Del("Authorization")
		request.Header.Del("Cookie")
		return nil
	}}}
}
func immutableURL(model inference.Model, raw string) (string, error) {
	source, err := url.Parse(model.Source)
	if err != nil || source.Scheme != "https" || source.Host != "huggingface.co" || source.User != nil || source.RawQuery != "" || source.Fragment != "" || source.RawPath != "" || !revisionHash.MatchString(model.Revision) {
		return "", errors.New("model source requires a pinned Hugging Face repository revision")
	}
	u, err := url.Parse(raw)
	if err != nil || !approvedDownloadURL(u) || u.Host != "huggingface.co" || u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("initial model URL must be an immutable Hugging Face artifact")
	}
	pieces := strings.Split(strings.Trim(source.Path, "/"), "/")
	if len(pieces) < 2 || pieces[0] == "" || pieces[1] == "" || strings.ContainsAny(source.Path, "\\\x00\r\n") {
		return "", errors.New("invalid model repository")
	}
	prefix := "/" + pieces[0] + "/" + pieces[1] + "/resolve/" + model.Revision + "/"
	if len(pieces) != 2 && (len(pieces) < 5 || pieces[2] != "resolve" || pieces[3] != model.Revision || source.Path != u.Path) {
		return "", errors.New("artifact source differs from the exact pinned download")
	}
	if !strings.HasPrefix(u.Path, prefix) || !strings.HasSuffix(strings.ToLower(u.Path), ".gguf") || len(u.Path) > 2048 {
		return "", errors.New("download URL does not match the approved model revision")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." || strings.ContainsAny(part, "\\\x00\r\n") {
			return "", errors.New("invalid artifact path")
		}
	}
	return u.String(), nil
}

func ensureModelRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("model root must be a dedicated absolute directory")
	}
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		parent, resolveErr := filepath.EvalSymlinks(filepath.Dir(root))
		if resolveErr != nil || parent != filepath.Dir(root) {
			return errors.New("model root parent must not traverse symlinks")
		}
		if err = os.Mkdir(root, 0700); err != nil {
			return err
		}
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return errors.New("model root must not traverse symlinks")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("model root must be a private directory")
	}
	return nil
}
func openRegular(path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open private regular model/config file")
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("expected a regular file")
	}
	return file, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func hashModel(ctx context.Context, path string, size uint64, expected string) error {
	if !artifactHash.MatchString(expected) || !filepath.IsAbs(path) {
		return errors.New("invalid model identity")
	}
	file, err := openRegular(path)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || uint64(before.Size()) != size || before.Mode().Perm()&0077 != 0 {
		return errors.New("model size or private permissions differ")
	}
	hash := sha256.New()
	if _, err = io.CopyBuffer(hash, contextReader{ctx, file}, make([]byte, 1<<20)); err != nil {
		return err
	}
	after, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(after, pathInfo) || before.ModTime() != after.ModTime() || after.Size() != before.Size() || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("model integrity changed")
	}
	return nil
}
func removeExactModel(path, expected string) error {
	if filepath.Base(path) != expected+".gguf" || !artifactHash.MatchString(expected) {
		return errors.New("refusing to remove an unrecognized model path")
	}
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("refusing to remove a nonregular model")
	}
	if err = hashModel(context.Background(), path, uint64(before.Size()), expected); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, current) || before.Size() != current.Size() || before.ModTime() != current.ModTime() {
		return errors.New("model changed before removal")
	}
	return os.Remove(path)
}
func diskCapacity(root string, size, maxBytes uint64) error {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 100000 {
		return errors.New("cannot inspect bounded model storage")
	}
	var used uint64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("model root must contain only regular model files")
		}
		if uint64(info.Size()) > 128<<30-used {
			return errors.New("model cache exceeds local bound")
		}
		used += uint64(info.Size())
	}
	if used > maxBytes*2 || size > maxBytes*2-used {
		return errors.New("model cache exceeds twice the local runtime memory budget")
	}
	var disk syscall.Statfs_t
	if syscall.Statfs(root, &disk) != nil || disk.Bsize <= 0 {
		return errors.New("cannot determine available model storage")
	}
	available := disk.Bavail * uint64(disk.Bsize)
	if size > available || 1<<30 > available-size {
		return errors.New("model download must leave at least1GiB free disk")
	}
	return nil
}
func (d *downloader) fetch(ctx context.Context, root string, model inference.Model, rawURL string, maxBytes uint64) (string, bool, error) {
	target := ""
	if err := ensureModelRoot(root); err != nil {
		return target, false, err
	}
	if model.SizeBytes < 24 || model.SizeBytes > maxBytes || model.SizeBytes > 64<<30 || !artifactHash.MatchString(model.SHA256) {
		return target, false, errors.New("artifact exceeds local download bound")
	}
	address, err := immutableURL(model, rawURL)
	if err != nil {
		return target, false, err
	}
	target = filepath.Join(root, model.SHA256+".gguf")
	if _, err = os.Lstat(target); err == nil {
		return target, false, hashModel(ctx, target, model.SizeBytes, model.SHA256)
	} else if !os.IsNotExist(err) {
		return "", false, err
	}
	if err = diskCapacity(root, model.SizeBytes, maxBytes); err != nil {
		return "", false, err
	}
	file, err := os.CreateTemp(root, ".hosted-model-")
	if err != nil {
		return "", false, err
	}
	name := file.Name()
	identity, _ := file.Stat()
	defer func() {
		file.Close()
		if current, e := os.Lstat(name); e == nil && os.SameFile(identity, current) {
			_ = os.Remove(name)
		}
	}()
	if err = file.Chmod(0600); err != nil {
		return "", false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", false, errors.New("invalid model download request")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := d.client.Do(request)
	if err != nil {
		return "", false, errors.New("model download failed over authenticated HTTPS")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || (response.ContentLength >= 0 && uint64(response.ContentLength) != model.SizeBytes) || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return "", false, errors.New("model download response size/status/encoding differs")
	}
	hash := sha256.New()
	written, err := io.CopyBuffer(io.MultiWriter(file, hash), io.LimitReader(contextReader{ctx, response.Body}, int64(model.SizeBytes)+1), make([]byte, 1<<20))
	if err != nil || uint64(written) != model.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != model.SHA256 {
		return "", false, errors.New("model download failed integrity verification")
	}
	if err = ctx.Err(); err != nil {
		return "", false, err
	}
	if err = file.Sync(); err != nil {
		return "", false, err
	}
	if err = file.Close(); err != nil {
		return "", false, err
	}
	if current, e := os.Lstat(name); e != nil || !os.SameFile(identity, current) {
		return "", false, errors.New("model temporary file changed")
	}
	if err = ctx.Err(); err != nil {
		return "", false, err
	}
	if err = os.Link(name, target); err != nil {
		if os.IsExist(err) {
			return target, false, hashModel(ctx, target, model.SizeBytes, model.SHA256)
		}
		return "", false, err
	}
	directory, err := os.Open(root)
	if err != nil {
		_ = removeExactModel(target, model.SHA256)
		return "", false, err
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		_ = removeExactModel(target, model.SHA256)
		return "", false, err
	}
	return target, true, nil
}

package inference

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// InstalledModel adds a local, explicitly provisioned file to public metadata.
// Nucleus never downloads or copies weights as a consequence of a request.
type InstalledModel struct {
	Model
	Path string `json:"path"`
}

func ValidateModel(m Model) error {
	if err := ValidateModelProvenance(m); err != nil {
		return err
	}
	return validateModelMetadata(m)
}

// validateModelMetadata is shared after the caller has established its provenance policy.
func validateModelMetadata(m Model) error {
	if m.ID == "" || len(m.ID) > 128 || strings.ContainsAny(m.ID, ",\x00\r\n") || m.Revision == "" || m.Source == "" || m.License == "" || m.Architecture == "" || m.Quantization == "" {
		return errors.New("model requires bounded id, revision, source, license, architecture, and quantization")
	}
	if m.Format != "GGUF" || m.Runtime != "llama.cpp" {
		return errors.New("initial runtime supports GGUF via llama.cpp only")
	}
	hash, err := hex.DecodeString(m.SHA256)
	if err != nil || len(hash) != sha256.Size || strings.ToLower(m.SHA256) != m.SHA256 {
		return errors.New("model requires lowercase SHA-256 integrity hash")
	}
	if m.SizeBytes == 0 || m.RequiredMemoryBytes < m.SizeBytes || m.RequiredMemoryBytes > 1<<60 {
		return errors.New("model requires file size and a valid memory estimate including context")
	}
	if len(m.Workloads) != 1 || m.Workloads[0] != "text-generation" {
		return errors.New("initial runtime supports text-generation workload only")
	}
	for _, v := range []string{m.Revision, m.Source, m.License, m.Architecture, m.Quantization} {
		if len(v) > 2048 || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("invalid model metadata")
		}
	}
	return nil
}

// GGUFInfo contains file metadata used for compatibility and an F16 KV-cache
// estimate. Unsupported/hybrid architectures require a future memory estimator.
type GGUFInfo struct {
	Version                                                                    uint32
	Architecture                                                               string
	FileType                                                                   uint64
	Layers, Embedding, Heads, KVHeads, KeyLength, ValueLength, TrainingContext uint64
	SizeBytes                                                                  uint64
	SHA256                                                                     string
}

func InspectGGUF(path string) (GGUFInfo, error) {
	var result GGUFInfo
	if !filepath.IsAbs(path) {
		return result, errors.New("model path must be absolute")
	}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Size() < 24 {
		return result, errors.New("model must be a regular GGUF file")
	}
	result.SizeBytes = uint64(info.Size())
	var magic [4]byte
	if _, err = io.ReadFull(f, magic[:]); err != nil {
		return result, err
	}
	if string(magic[:]) != "GGUF" {
		return result, errors.New("model is not a little-endian GGUF file")
	}
	if err = binary.Read(f, binary.LittleEndian, &result.Version); err != nil {
		return result, err
	}
	if result.Version != 2 && result.Version != 3 {
		return result, fmt.Errorf("unsupported GGUF version %d", result.Version)
	}
	var tensors, count uint64
	if err = binary.Read(f, binary.LittleEndian, &tensors); err != nil {
		return result, err
	}
	if err = binary.Read(f, binary.LittleEndian, &count); err != nil {
		return result, err
	}
	if tensors == 0 || tensors > 1_000_000 || count > 1_000_000 {
		return result, errors.New("invalid GGUF tensor or metadata count")
	}
	numbers := map[string]uint64{}
	for i := uint64(0); i < count; i++ {
		key, e := ggufString(f, 1024)
		if e != nil {
			return result, e
		}
		var typ uint32
		if e = binary.Read(f, binary.LittleEndian, &typ); e != nil {
			return result, e
		}
		if key == "general.architecture" && typ == 8 {
			result.Architecture, e = ggufString(f, 128)
			if e != nil {
				return result, e
			}
		} else if typ == 4 || typ == 10 {
			var n uint64
			if typ == 4 {
				var v uint32
				e = binary.Read(f, binary.LittleEndian, &v)
				n = uint64(v)
			} else {
				e = binary.Read(f, binary.LittleEndian, &n)
			}
			if e != nil {
				return result, e
			}
			numbers[key] = n
		} else if e = ggufSkip(f, typ, 0, info.Size()); e != nil {
			return result, e
		}
	}
	result.FileType = numbers["general.file_type"]
	prefix := result.Architecture + "."
	result.Layers = numbers[prefix+"block_count"]
	result.Embedding = numbers[prefix+"embedding_length"]
	result.Heads = numbers[prefix+"attention.head_count"]
	result.KVHeads = numbers[prefix+"attention.head_count_kv"]
	result.KeyLength = numbers[prefix+"attention.key_length"]
	result.ValueLength = numbers[prefix+"attention.value_length"]
	result.TrainingContext = numbers[prefix+"context_length"]
	if result.KVHeads == 0 {
		result.KVHeads = result.Heads
	}
	if result.Heads > 0 && result.KeyLength == 0 {
		result.KeyLength = result.Embedding / result.Heads
	}
	if result.Heads > 0 && result.ValueLength == 0 {
		result.ValueLength = result.Embedding / result.Heads
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return result, err
	}
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return result, nil
}

func ggufString(f *os.File, max uint64) (string, error) {
	var n uint64
	if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	if n > max {
		return "", errors.New("GGUF metadata string exceeds bound")
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(f, b)
	return string(b), err
}
func ggufSkip(f *os.File, typ uint32, depth int, size int64) error {
	var n uint64
	switch typ {
	case 0, 1, 7:
		n = 1
	case 2, 3:
		n = 2
	case 4, 5, 6:
		n = 4
	case 10, 11, 12:
		n = 8
	case 8:
		if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
			return err
		}
	case 9:
		if depth > 0 {
			return errors.New("nested GGUF arrays are unsupported")
		}
		var element uint32
		var count uint64
		if err := binary.Read(f, binary.LittleEndian, &element); err != nil {
			return err
		}
		if err := binary.Read(f, binary.LittleEndian, &count); err != nil {
			return err
		}
		if count > 2_000_000 {
			return errors.New("GGUF metadata array exceeds bound")
		}
		for i := uint64(0); i < count; i++ {
			if err := ggufSkip(f, element, depth+1, size); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown GGUF metadata type %d", typ)
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if n > uint64(size) || pos > size-int64(n) {
		return io.ErrUnexpectedEOF
	}
	_, err = f.Seek(int64(n), io.SeekCurrent)
	return err
}

// minimumMemory includes whole model, explicit F16 K/V context cache, 25% file
// overhead, and 256 MiB compute allowance. This is an estimate, never throughput
// or a guarantee; a configured hard address-space limit remains authoritative.
func (g GGUFInfo) minimumMemory(context int) (uint64, error) {
	switch g.Architecture {
	case "llama", "qwen2", "qwen3", "gemma", "gemma2", "gemma3", "mistral", "phi2", "phi3", "stablelm":
	default:
		return 0, fmt.Errorf("memory estimator does not support architecture %q", g.Architecture)
	}
	if context < 1 || g.Layers == 0 || g.Heads == 0 || g.KVHeads == 0 || g.KeyLength == 0 || g.ValueLength == 0 {
		return 0, errors.New("GGUF lacks transformer dimensions needed for a memory estimate")
	}
	if g.TrainingContext > 0 && uint64(context) > g.TrainingContext {
		return 0, errors.New("configured context exceeds model training context")
	}
	kv := uint64(context)
	for _, factor := range []uint64{g.Layers, g.KVHeads, 2, g.KeyLength + g.ValueLength} {
		if factor == 0 || kv > math.MaxUint64/factor {
			return 0, errors.New("model memory estimate overflow")
		}
		kv *= factor
	}
	overhead := g.SizeBytes/4 + (256 << 20)
	if g.SizeBytes > math.MaxUint64-overhead || g.SizeBytes+overhead > math.MaxUint64-kv {
		return 0, errors.New("model memory estimate overflow")
	}
	return g.SizeBytes + overhead + kv, nil
}

func validateInstalled(m InstalledModel, context int) (InstalledModel, error) {
	if err := ValidateModel(m.Model); err != nil {
		return m, err
	}
	return inspectInstalledModel(m, context)
}

// validateApprovedInstalled is reserved for owner-configured execution boundaries.
// Admission, including any exact-hash disclosure exception, precedes model I/O.
func validateApprovedInstalled(m InstalledModel, context int, approvals []ModelApproval) (InstalledModel, error) {
	if err := ApproveModel(m.Model, approvals); err != nil {
		return m, err
	}
	if err := validateModelMetadata(m.Model); err != nil {
		return m, err
	}
	return inspectInstalledModel(m, context)
}

// inspectInstalledModel always enforces the same file, GGUF and memory checks.
func inspectInstalledModel(m InstalledModel, context int) (InstalledModel, error) {
	g, err := InspectGGUF(m.Path)
	if err != nil {
		return m, err
	}
	if g.SHA256 != m.SHA256 || g.SizeBytes != m.SizeBytes {
		return m, errors.New("installed model integrity hash or file size does not match catalog")
	}
	quantizations := map[uint64]string{2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1", 10: "Q2_K", 11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M", 18: "Q6_K", 19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S", 22: "IQ3_XS", 23: "IQ3_XXS", 24: "IQ1_S", 25: "IQ4_NL", 26: "IQ3_S", 27: "IQ3_M", 28: "IQ2_S", 29: "IQ2_M", 30: "IQ4_XS", 31: "IQ1_M"}
	if quantizations[g.FileType] == "" || quantizations[g.FileType] != m.Quantization {
		return m, errors.New("GGUF quantization is unsupported or does not match catalog")
	}
	if g.Architecture != m.Architecture {
		return m, errors.New("GGUF architecture does not match catalog")
	}
	minimum, err := g.minimumMemory(context)
	if err != nil {
		return m, err
	}
	if m.RequiredMemoryBytes < minimum {
		return m, fmt.Errorf("model memory estimate too small: need at least %d bytes for file, context and runtime allowance", minimum)
	}
	return m, nil
}

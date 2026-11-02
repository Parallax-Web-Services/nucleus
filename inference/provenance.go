package inference

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ModelOrigin identifies one upstream model, including a base, merge input,
// adapter, or distillation teacher. Revision and evidence must be reviewed by
// the operator; runtime admission does not contact these URLs.
type ModelOrigin struct {
	ID        string   `json:"id"`
	Revision  string   `json:"revision"`
	Publisher string   `json:"publisher"`
	Country   string   `json:"country"`
	Source    string   `json:"source"`
	SHA256    string   `json:"sha256,omitempty"`
	Evidence  []string `json:"evidence"`
}

// ModelProvenance is an operator attestation, not a geography classifier.
// BaseModels enumerates the reviewed upstream model lineage, including teachers,
// merged weights and adapters. Publisher-disclosed lineage preserves explicitly
// incomplete disclosure and requires a separate exact-hash owner exception.
// An original model uses an explicit empty array. Software/hardware are outside
// this policy.
type ModelProvenance struct {
	Publisher         string        `json:"publisher"`
	Country           string        `json:"country"`
	Evidence          []string      `json:"evidence"`
	LineageComplete   bool          `json:"lineage_complete"`
	LineageDisclosure string        `json:"lineage_disclosure,omitempty"`
	BaseModels        []ModelOrigin `json:"base_models"`
}

// ModelApproval belongs to the owner-controlled allowlist. A hash is approved
// together with the reviewed provenance; a worker cannot replace the attestation
// with different country or lineage claims while retaining the approved hash.
type ModelApproval struct {
	SHA256                         string          `json:"sha256"`
	Provenance                     ModelProvenance `json:"provenance"`
	AllowPublisherDisclosedLineage bool            `json:"allow_publisher_disclosed_lineage,omitempty"`
	ReviewNote                     string          `json:"review_note,omitempty"`
}

const blockedQwenSHA256 = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"

// This bounded curated guard catches known publisher and weight-family aliases.
// It is supplementary to mandatory owner review and is deliberately not claimed
// to identify every Chinese-origin model. Matching never examines a runtime,
// software dependency, CPU, accelerator, or model architecture field.
var blockedModelIdentities = []string{
	"alibaba", "aliyun", "qwen", "qianwen", "tongyi", "deepseek",
	"bytedance", "doubao", "seedoss", "minimax", "zhipu", "zaiorg", "chatglm",
	"moonshot", "baidu", "ernie", "tencent", "hunyuan", "baai",
	"beijingacademyofartificialintelligence", "internlm", "internvl", "opengvlab",
	"shanghaiailab", "shanghaiartificialintelligencelaboratory", "modelbest",
	"minicpm", "openbmb", "stepfun", "sensetime", "sensenova", "iflytek",
	"thudm", "cogview", "cogvideo", "ipadapter", "01ai", "zerooneai",
	"阿里巴巴", "通义千问", "深度求索", "字节跳动", "智谱", "月之暗面",
	"百度", "腾讯", "北京智源", "零一万物", "阶跃星辰", "商汤", "科大讯飞",
}
var blockedShortFamilies = regexp.MustCompile(`(?i)(^|[^a-z0-9])(glm|kimi|yi|bge)([0-9._/ -]|$)|(^|[^a-z0-9])(seed|step)[._ -]?[0-9]|(^|[^a-z0-9])h94([^a-z0-9]|$)`)

// ISO 3166-1 alpha-2 codes, including separately coded jurisdictions. Unknown
// placeholders and non-codes are rejected. The user policy excludes CN, HK and
// MO explicitly; this is not a statement about the origin of software/hardware.
const isoCountries = " AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW "

func ValidateModelProvenance(m Model) error {
	return validateModelProvenance(m, false)
}

func validateModelProvenance(m Model, allowPublisherDisclosed bool) error {
	if err := checkModelHash(m.SHA256); err != nil {
		return err
	}
	for _, identity := range []string{m.ID, m.Source} {
		if deniedModelIdentity(identity) {
			return fmt.Errorf("model %q is blocked by the Chinese-origin model and derivative policy", m.ID)
		}
	}
	if m.Provenance == nil {
		return errors.New("model provenance is required; unknown model origin or lineage is not eligible")
	}
	return validateProvenance(*m.Provenance, allowPublisherDisclosed)
}

func ValidateModelApproval(a ModelApproval) error {
	if err := checkModelHash(a.SHA256); err != nil {
		return err
	}
	if a.ReviewNote != "" && !validProvenanceText(a.ReviewNote, 2000) {
		return errors.New("owner review_note must be bounded nonempty text")
	}
	if a.AllowPublisherDisclosedLineage {
		if !validProvenanceText(a.ReviewNote, 2000) {
			return errors.New("publisher-disclosed lineage exception requires an explicit bounded owner review_note")
		}
		if a.Provenance.LineageComplete || a.Provenance.LineageDisclosure != "publisher-disclosed" {
			return errors.New("owner disclosure exception requires lineage_complete=false and lineage_disclosure=publisher-disclosed")
		}
	}
	return validateProvenance(a.Provenance, a.AllowPublisherDisclosedLineage)
}

// ApproveModel checks both immutable artifact identity and the owner's reviewed
// attestation. An empty allowlist does not implicitly approve any model.
func ApproveModel(m Model, approvals []ModelApproval) error {
	// First check all origin/identity guards while retaining an honest incomplete
	// disclosure. It can become eligible only through its exact matching owner
	// entry below; a runtime-provided disclosure never grants its own exception.
	if err := validateModelProvenance(m, true); err != nil {
		return err
	}
	if len(approvals) > 256 {
		return errors.New("owner model approval list exceeds 256 entries")
	}
	current, err := canonicalProvenance(*m.Provenance)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	matched := false
	for _, a := range approvals {
		if err = ValidateModelApproval(a); err != nil {
			return fmt.Errorf("invalid owner model approval: %w", err)
		}
		if seen[a.SHA256] {
			return errors.New("duplicate owner model approval hash")
		}
		seen[a.SHA256] = true
		if a.SHA256 != m.SHA256 {
			continue
		}
		reviewed, e := canonicalProvenance(a.Provenance)
		if e != nil {
			return e
		}
		if !bytes.Equal(current, reviewed) {
			return errors.New("worker model provenance differs from the owner-approved publisher, country or lineage disclosure")
		}
		if !m.Provenance.LineageComplete && !a.AllowPublisherDisclosedLineage {
			return errors.New("publisher-disclosed model lineage requires a matching exact-hash owner exception")
		}
		matched = true
	}
	if !matched {
		return errors.New("model SHA-256 is not owner-approved; review its complete provenance and add approved_models")
	}
	return nil
}

func checkModelHash(hash string) error {
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != 32 || strings.ToLower(hash) != hash {
		return errors.New("model provenance requires a lowercase SHA-256 artifact hash")
	}
	if hash == blockedQwenSHA256 {
		return errors.New("known Qwen artifact hash is blocked by the Chinese-origin model and derivative policy, including renamed copies")
	}
	return nil
}

func validateProvenance(p ModelProvenance, allowPublisherDisclosed bool) error {
	if err := validateOriginPublisher(p.Publisher, p.Country, p.Evidence); err != nil {
		return err
	}
	switch p.LineageDisclosure {
	case "":
	case "publisher-disclosed":
		if p.LineageComplete {
			return errors.New("publisher-disclosed lineage must remain explicitly incomplete")
		}
	default:
		return errors.New("unsupported model lineage disclosure")
	}
	if (!p.LineageComplete && (!allowPublisherDisclosed || p.LineageDisclosure != "publisher-disclosed")) || p.BaseModels == nil {
		return errors.New("model requires complete reviewed lineage or an exact-hash owner-approved publisher-disclosed exception (base_models must be an array)")
	}
	if len(p.BaseModels) > 64 {
		return errors.New("model lineage exceeds 64 upstream model entries")
	}
	seen := map[string]bool{}
	for _, base := range p.BaseModels {
		if !validProvenanceText(base.ID, 256) || !validProvenanceText(base.Revision, 256) {
			return errors.New("every upstream model requires a bounded identifier and revision")
		}
		if deniedModelIdentity(base.ID) || deniedModelIdentity(base.Source) {
			return fmt.Errorf("upstream model %q is blocked by the Chinese-origin model and derivative policy", base.ID)
		}
		if err := validateOriginPublisher(base.Publisher, base.Country, base.Evidence); err != nil {
			return fmt.Errorf("upstream model %q: %w", base.ID, err)
		}
		source, err := evidenceURL(base.Source)
		if err != nil {
			return fmt.Errorf("upstream model %q requires a valid HTTPS source URL: %w", base.ID, err)
		}
		if base.SHA256 != "" {
			if err = checkModelHash(base.SHA256); err != nil {
				return fmt.Errorf("upstream model %q: %w", base.ID, err)
			}
		}
		identity := base.ID + "\x00" + base.Revision + "\x00" + source
		if seen[identity] {
			return errors.New("duplicate upstream model lineage entry")
		}
		seen[identity] = true
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(encoded) > 64<<10 {
		return errors.New("model provenance exceeds 64 KiB")
	}
	return nil
}

func validateOriginPublisher(publisher, country string, evidence []string) error {
	if !validProvenanceText(publisher, 256) {
		return errors.New("model publisher is required and must be bounded text")
	}
	switch strings.ToLower(publisher) {
	case "unknown", "unverified", "unspecified", "none", "n/a", "na", "null":
		return errors.New("unknown model publisher is not eligible")
	}
	if len(country) != 2 || strings.ToUpper(country) != country || !strings.Contains(isoCountries, " "+country+" ") {
		return errors.New("model publisher country must be a known uppercase ISO 3166-1 alpha-2 code; unknown origin is not eligible")
	}
	if country == "CN" || country == "HK" || country == "MO" {
		return fmt.Errorf("publisher jurisdiction %s is blocked by the Chinese-origin model and derivative policy", country)
	}
	if deniedModelIdentity(publisher) {
		return fmt.Errorf("model publisher %q is blocked by the Chinese-origin model and derivative policy", publisher)
	}
	if len(evidence) < 1 || len(evidence) > 8 {
		return errors.New("model publisher and origin require 1..8 reviewed HTTPS evidence URLs")
	}
	seen := map[string]bool{}
	for _, raw := range evidence {
		value, err := evidenceURL(raw)
		if err != nil {
			return fmt.Errorf("invalid provenance evidence: %w", err)
		}
		if seen[value] {
			return errors.New("duplicate provenance evidence URL")
		}
		seen[value] = true
	}
	return nil
}

func validProvenanceText(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func evidenceURL(raw string) (string, error) {
	if !validProvenanceText(raw, 2048) {
		return "", errors.New("evidence URL is missing, malformed or oversized")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.Contains(raw, "#") {
		return "", errors.New("only absolute HTTPS URLs without credentials or fragments are permitted")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("invalid HTTPS evidence port")
		}
	}
	if _, err = url.ParseQuery(u.RawQuery); err != nil {
		return "", errors.New("invalid HTTPS evidence query")
	}
	for _, value := range []string{u.Path, u.RawQuery} {
		decoded, e := url.QueryUnescape(value)
		if e != nil {
			return "", errors.New("invalid URL escaping")
		}
		for _, r := range decoded {
			if unicode.IsControl(r) {
				return "", errors.New("control character in evidence URL")
			}
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = u.Query().Encode()
	return u.String(), nil
}

func deniedModelIdentity(identity string) bool {
	// Decode percent-escaped repository identifiers before matching known aliases.
	value := identity
	for i := 0; i < 2; i++ {
		decoded, err := url.PathUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	lower := strings.ToLower(value)
	var normalized strings.Builder
	for _, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}
	compact := normalized.String()
	for _, alias := range blockedModelIdentities {
		if strings.Contains(compact, alias) {
			return true
		}
	}
	if compact == "zai" || blockedShortFamilies.MatchString(lower) {
		return true
	}
	if parsed, err := url.Parse(value); err == nil {
		host := strings.ToLower(parsed.Hostname())
		if host == "z.ai" || strings.HasSuffix(host, ".z.ai") {
			return true
		}
	}
	return false
}

// Canonicalization permits harmless evidence/base ordering differences while
// binding every substantive publisher, jurisdiction and lineage field.
func canonicalProvenance(p ModelProvenance) ([]byte, error) {
	copy := p
	copy.Evidence = make([]string, len(p.Evidence))
	for i, raw := range p.Evidence {
		value, err := evidenceURL(raw)
		if err != nil {
			return nil, err
		}
		copy.Evidence[i] = value
	}
	sort.Strings(copy.Evidence)
	copy.BaseModels = make([]ModelOrigin, len(p.BaseModels))
	for i, base := range p.BaseModels {
		copy.BaseModels[i] = base
		value, err := evidenceURL(base.Source)
		if err != nil {
			return nil, err
		}
		copy.BaseModels[i].Source = value
		copy.BaseModels[i].Evidence = make([]string, len(base.Evidence))
		for j, raw := range base.Evidence {
			value, err = evidenceURL(raw)
			if err != nil {
				return nil, err
			}
			copy.BaseModels[i].Evidence[j] = value
		}
		sort.Strings(copy.BaseModels[i].Evidence)
	}
	sort.Slice(copy.BaseModels, func(i, j int) bool {
		left, _ := json.Marshal(copy.BaseModels[i])
		right, _ := json.Marshal(copy.BaseModels[j])
		return string(left) < string(right)
	})
	return json.Marshal(copy)
}

package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/srsc/constant"
	"golang.org/x/sync/errgroup"
)

const (
	bgpViewURLTemplate    = "https://api.bgpview.io/asn/%s/prefixes"
	ripeURLTemplate       = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s"
	statusOK              = "ok"
	maxResponseBodyBytes  = 4 << 20
	clientRequestTimeout  = 15 * time.Second
	defaultConcurrencyCap = 10
)

type ASNPrefix struct {
	Prefix string `json:"prefix"`
}

type BGPViewResponse struct {
	Status string `json:"status"`
	Data   struct {
		IPv4Prefixes []ASNPrefix `json:"ipv4_prefixes"`
		IPv6Prefixes []ASNPrefix `json:"ipv6_prefixes"`
	} `json:"data"`
}

type RIPEResponse struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []ASNPrefix `json:"prefixes"`
	} `json:"data"`
}

type ASNResolver struct {
	cache     sync.Map
	client    *http.Client
	userAgent string
}

func NewASNResolver() *ASNResolver {
	return &ASNResolver{
		client: &http.Client{
			Timeout: clientRequestTimeout,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		userAgent: F.ToString("srsc/", constant.Version, "(sing-box ", constant.CoreVersion(), ")"),
	}
}

func (r *ASNResolver) normalizeASN(asn string) string {
	asn = strings.TrimSpace(asn)
	asn = strings.TrimPrefix(asn, "AS")
	asn = strings.TrimPrefix(asn, "as")
	asn = strings.TrimSuffix(asn, "AS")
	asn = strings.TrimSuffix(asn, "as")
	return strings.TrimSpace(asn)
}

func (r *ASNResolver) validateASN(asn string) error {
	if asn == "" {
		return E.New("ASN cannot be empty")
	}
	if _, err := strconv.ParseUint(asn, 10, 32); err != nil {
		return E.Cause(err, "invalid ASN format: ", asn)
	}
	return nil
}

func (r *ASNResolver) fetchFromBGPView(ctx context.Context, asnID string) ([]string, error) {
	var response BGPViewResponse
	if err := r.fetchJSON(ctx, fmt.Sprintf(bgpViewURLTemplate, asnID), "BGPView", &response); err != nil {
		return nil, err
	}
	if response.Status != statusOK {
		return nil, E.New("BGPView API returned status: ", response.Status)
	}

	totalPrefixes := len(response.Data.IPv4Prefixes) + len(response.Data.IPv6Prefixes)
	prefixes := make([]string, 0, totalPrefixes)

	for _, prefix := range response.Data.IPv4Prefixes {
		if prefix.Prefix != "" {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}
	for _, prefix := range response.Data.IPv6Prefixes {
		if prefix.Prefix != "" {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}

	return prefixes, nil
}

func (r *ASNResolver) fetchFromRIPE(ctx context.Context, asnID string) ([]string, error) {
	var response RIPEResponse
	if err := r.fetchJSON(ctx, fmt.Sprintf(ripeURLTemplate, asnID), "RIPE", &response); err != nil {
		return nil, err
	}
	if response.Status != statusOK {
		return nil, E.New("RIPE API returned status: ", response.Status)
	}

	prefixes := make([]string, 0, len(response.Data.Prefixes))
	for _, prefix := range response.Data.Prefixes {
		if prefix.Prefix != "" {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}

	return prefixes, nil
}

func (r *ASNResolver) fetchJSON(ctx context.Context, url, apiName string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return E.Cause(err, "create ", apiName, " request")
	}
	req.Header.Set("User-Agent", r.userAgent)

	resp, err := r.client.Do(req)
	if err != nil {
		return E.Cause(err, "fetch ", apiName, " API")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return E.New(apiName, " API returned status: ", resp.Status)
	}

	reader := io.LimitReader(resp.Body, maxResponseBodyBytes)
	if err := json.NewDecoder(reader).Decode(target); err != nil {
		return E.Cause(err, "decode ", apiName, " response")
	}

	return nil
}

func (r *ASNResolver) ResolveASN(ctx context.Context, asn string) ([]string, error) {
	asnID := r.normalizeASN(asn)
	if err := r.validateASN(asnID); err != nil {
		return nil, err
	}

	if prefixes, ok := r.loadFromCache(asnID); ok {
		return prefixes, nil
	}

	if prefixes, err := r.fetchFromBGPView(ctx, asnID); err == nil && len(prefixes) > 0 {
		r.cache.Store(asnID, slices.Clone(prefixes))
		return prefixes, nil
	}

	if prefixes, err := r.fetchFromRIPE(ctx, asnID); err == nil && len(prefixes) > 0 {
		r.cache.Store(asnID, slices.Clone(prefixes))
		return prefixes, nil
	}

	empty := make([]string, 0)
	r.cache.Store(asnID, empty)
	return empty, nil
}

func (r *ASNResolver) loadFromCache(asnID string) ([]string, bool) {
	if cached, ok := r.cache.Load(asnID); ok {
		if prefixes, ok := cached.([]string); ok {
			return slices.Clone(prefixes), true
		}
	}
	return nil, false
}

func (r *ASNResolver) ResolveASNs(ctx context.Context, asns []string) ([]string, error) {
	if len(asns) == 0 {
		return nil, nil
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(defaultConcurrencyCap)

	var (
		mu          sync.Mutex
		allPrefixes []string
	)

	for _, asnValue := range asns {
		asnValue := asnValue
		g.Go(func() error {
			prefixes, err := r.ResolveASN(ctx, asnValue)
			if err != nil {
				return E.Cause(err, "resolve ASN: ", asnValue)
			}

			if len(prefixes) == 0 {
				return nil
			}

			mu.Lock()
			allPrefixes = append(allPrefixes, prefixes...)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return allPrefixes, err
	}

	return allPrefixes, nil
}

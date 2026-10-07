package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/go-macos-codesign/pkg/codesign"
)

const metadataMeasurementEnv = "MACOSCODESIGN_METADATA_MEASUREMENT"
const metadataMeasurementPrefix = "METADATA_MEASUREMENT="

type metadataMeasurementRequest struct {
	Path, TemporaryDirectory string
	Budget                   int64
	TrustedCertificates      [][]byte
}
type metadataMeasurement struct {
	CDHash                                       string
	DirectorySize                                int64
	AllocatedBytes, SampledHeapPeak, ProcessPeak uint64
	Elapsed                                      time.Duration
	Storage                                      codesign.WorkingStorageStats
}

// The existing acceptance case runs this child branch with one explicit request.
// Fixture construction and native/CLI comparisons stay in the parent. Every
// measurement therefore starts in a fresh process with no previous large case.
func metadataMeasurementWorker(t *testing.T, request string) {
	t.Helper()
	var input metadataMeasurementRequest
	if err := json.Unmarshal([]byte(request), &input); err != nil {
		t.Fatal(err)
	}
	var result metadataMeasurement
	ctx := codesign.WithWorkingStorage(t.Context(), codesign.WorkingStorageOptions{MemoryBytes: input.Budget, TemporaryDirectory: input.TemporaryDirectory, Observe: func(s codesign.WorkingStorageStats) { result.Storage = s }})
	runtime.GC() // Isolated test process only; library operations never tune the GC.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	peak := before.HeapAlloc
	stop := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Go(func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				peak = max(peak, sample.HeapAlloc)
			}
		}
	})
	start := time.Now()
	calls := 0
	err := codesign.VisitVerification(ctx, input.Path, codesign.VerifyOptions{TrustedCertificates: input.TrustedCertificates}, func(r *codesign.Report, err error) error {
		calls++
		if err != nil {
			return err
		}
		if r == nil || !r.Valid || len(r.Architectures) != 1 || len(r.Architectures[0].Signature.Directories) != 1 {
			return fmt.Errorf("invalid borrowed metadata report")
		}
		d := r.Architectures[0].Signature.Directories[0]
		if d.Raw != nil {
			return fmt.Errorf("materialized borrowed CodeDirectory")
		}
		result.DirectorySize, result.CDHash = d.Size(), d.CDHash
		return nil
	})
	result.Elapsed = time.Since(start)
	close(stop)
	sampler.Wait()
	if err != nil || calls != 1 {
		t.Fatal("isolated verification failed", calls, err)
	}
	runtime.ReadMemStats(&after)
	result.AllocatedBytes = after.TotalAlloc - before.TotalAlloc
	result.SampledHeapPeak = max(peak, after.HeapAlloc)
	result.ProcessPeak, err = processPeakMemory(t.Context())
	if err != nil || result.ProcessPeak == 0 {
		t.Fatal("process memory observation", result.ProcessPeak, err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(metadataMeasurementPrefix + string(data))
}

func measureMetadataProcess(t *testing.T, path, temp string, budget int64, trusted [][]byte) metadataMeasurement {
	t.Helper()
	request, err := json.Marshal(metadataMeasurementRequest{Path: path, TemporaryDirectory: temp, Budget: budget, TrustedCertificates: trusted})
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSignatureMetadataBoundaries$", "-test.count=1")
	cmd.Env = append(os.Environ(), metadataMeasurementEnv+"="+string(request))
	out, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("isolated memory worker: error=%v context=%v\n%s", err, ctx.Err(), out)
	}
	var result metadataMeasurement
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		if data, match := strings.CutPrefix(line, metadataMeasurementPrefix); match {
			if found {
				t.Fatal("duplicate memory measurement")
			}
			found = true
			if err := json.Unmarshal([]byte(data), &result); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || result.ProcessPeak == 0 {
		t.Fatalf("missing memory measurement: %s", out)
	}
	return result
}

package nucleusapp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inference"
)

// prepareInference returns a synchronous cleanup barrier. Cancelling a context
// alone does not wait for goroutines or exec.CommandContext to reap a child
// before main exits, so every serve return must invoke this barrier.
func prepareInference(ctx context.Context, home string, state *fabric.State, path, address string) (service *inference.Service, cleanup func(), prepareErr error) {
	if path == "" {
		return nil, func() {}, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var backend inference.Backend
	var running sync.WaitGroup
	var cleanupOnce sync.Once
	cleanup = func() {
		cleanupOnce.Do(func() {
			cancel()
			if backend != nil {
				_ = backend.Close()
			}
			running.Wait()
		})
	}
	defer func() {
		if prepareErr != nil {
			cleanup()
		}
	}()
	cfg, err := inference.LoadFleetConfig(path)
	if err != nil {
		return nil, cleanup, err
	}
	owner := state.NodeID == state.OwnerID
	if !owner && cfg.Meld != nil {
		return nil, cleanup, errors.New("Meld bridge belongs on the owner; remote image jobs are not implemented")
	}
	var control inference.WorkerControl
	if owner {
		scheduler, err := inference.NewScheduler(state.NodeID, cfg, func(id string) bool {
			current, e := fabric.Load(home)
			if e != nil || current.FabricID != state.FabricID {
				return false
			}
			_, ok := current.Members[id]
			return ok
		})
		if err != nil {
			return nil, cleanup, err
		}
		service = &inference.Service{Scheduler: scheduler, APIKey: cfg.APIKey}
		if cfg.Meld != nil {
			service.Meld, err = inference.NewMeldAdapter(*cfg.Meld)
			if err != nil {
				return nil, cleanup, err
			}
		}
		url, err := inference.StartAPI(ctx, address, service)
		if err != nil {
			return nil, cleanup, err
		}
		fmt.Printf("Inference: authenticated client API on %s\n", url)
		running.Add(1)
		go func() { defer running.Done(); scheduler.Run(ctx) }()
		control = inference.LocalControl{Scheduler: scheduler, NodeID: state.NodeID}
	} else {
		control, err = inference.NewRemoteControl(home)
		if err != nil {
			return nil, cleanup, err
		}
	}
	if cfg.Runtime != nil {
		backend, err = inference.NewRuntime(ctx, *cfg.Runtime)
		if err != nil {
			return nil, cleanup, err
		}
		running.Add(1)
		go func() {
			defer running.Done()
			defer backend.Close()
			lastError := time.Time{}
			var errorMu sync.Mutex
			_ = inference.RunWorker(ctx, backend, control, *cfg.Runtime, inference.ReadBenchmarks(home), func(err error) {
				errorMu.Lock()
				defer errorMu.Unlock()
				if time.Since(lastError) > 5*time.Second {
					fmt.Fprintln(os.Stderr, "inference worker:", err)
					lastError = time.Now()
				}
			})
		}()
	} else if !owner {
		return nil, cleanup, errors.New("worker inference config requires an explicitly provisioned runtime")
	}
	return service, cleanup, nil
}
func benchmarkCommand(home string, args []string) error {
	var config, model, prompt string
	var maxTokens int
	rest, err := options("benchmark", args, func(f *flag.FlagSet) {
		f.StringVar(&config, "config", "", "private inference config")
		f.StringVar(&model, "model", "", "explicitly provisioned model")
		f.StringVar(&prompt, "prompt", "Explain how CPU inference uses quantized models in a short paragraph.", "benchmark prompt")
		f.IntVar(&maxTokens, "max-tokens", 32, "bounded output length")
	})
	if err != nil {
		return err
	}
	if len(rest) > 0 || config == "" || model == "" || maxTokens < 1 {
		return errors.New("usage: nucleus benchmark --config CONFIG --model ID [--max-tokens 32]")
	}
	if _, err = fabric.Load(home); err != nil {
		return err
	}
	cfg, err := inference.LoadFleetConfig(config)
	if err != nil {
		return err
	}
	if cfg.Runtime == nil {
		return errors.New("benchmark requires a provisioned local runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	backend, err := inference.NewRuntime(ctx, *cfg.Runtime)
	if err != nil {
		return err
	}
	defer backend.Close()
	result, err := inference.BenchmarkBackend(ctx, backend, model, prompt, maxTokens, cfg.ApprovedModels)
	if err != nil {
		return err
	}
	if err = inference.SaveBenchmark(home, result); err != nil {
		return err
	}
	return printJSON(result)
}

func validateModelsCommand(args []string) error {
	var path string
	rest, err := options("validate-models", args, func(f *flag.FlagSet) { f.StringVar(&path, "config", "", "private inference catalog config") })
	if err != nil {
		return err
	}
	if path == "" || len(rest) > 0 {
		return errors.New("usage: nucleus validate-models --config CONFIG")
	}
	cfg, err := inference.LoadFleetConfig(path)
	if err != nil {
		return err
	}
	if err = inference.ValidateConfiguredModels(cfg); err != nil {
		return err
	}
	return printJSON(map[string]any{"status": "approved", "model_count": len(cfg.Runtime.Models), "scope": "models_and_model_derivatives"})
}

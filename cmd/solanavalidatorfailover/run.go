package solanavalidatorfailover

import (
	"fmt"

	"github.com/sol-strategies/solana-validator-failover/internal/validator"
	"github.com/spf13/cobra"
)

var (
	// Validator available to all commands
	notADrill             bool
	noWaitForHealthy      bool
	noMinTimeToLeaderSlot bool
	skipTowerSync         bool
	autoConfirm           bool
	rollbackEnabled       bool
	toPeer                string
	runCmd                = &cobra.Command{
		Use:          "run",
		Short:        "run a failover - automatically detects what to do based on the node's role (active or passive)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if loadedConfig == nil {
				return fmt.Errorf("config was not loaded before running command")
			}

			v, err := validator.NewFromConfig(&loadedConfig.Validator)
			if err != nil {
				return fmt.Errorf("failed to create validator: %w", err)
			}

			err = v.Failover(validator.FailoverParams{
				NotADrill:             notADrill, // ignored when run on active node
				NoWaitForHealthy:      noWaitForHealthy,
				NoMinTimeToLeaderSlot: noMinTimeToLeaderSlot, // ignored when run on passive node
				SkipTowerSync:         skipTowerSync,
				AutoConfirm:           autoConfirm,
				RollbackEnabled:       rollbackEnabled,
				ToPeer:                toPeer,
			})
			if err != nil {
				return fmt.Errorf("failed to failover: %w", err)
			}
			return nil
		},
	}
)

func init() {
	runCmd.Flags().BoolVar(&notADrill, "not-a-drill", false, "execute failover for real (not a drill)")
	runCmd.Flags().BoolVar(&noWaitForHealthy, "no-wait-for-healthy", false, "don't wait for node to report being healthy by calling <config.validator.rpc_address>/health")
	runCmd.Flags().BoolVar(&noMinTimeToLeaderSlot, "no-min-time-to-leader-slot", false, "when run on an active node, don't wait until it has no leader slots in the next <config.validator.min_time_to_leader_slot> (default: 5m) - ignored when run on a passive node")
	runCmd.Flags().BoolVar(&skipTowerSync, "skip-tower-sync", false, "deprecated: native handovers negotiate the slot guard automatically; rejected for Agave-only pairs")
	runCmd.Flags().BoolVarP(&autoConfirm, "yes", "y", false, "automatically answer yes to all prompts")
	runCmd.Flags().BoolVarP(&rollbackEnabled, "rollback-enabled", "r", false, "deprecated: automatic rollback is rejected by the fenced protocol")
	runCmd.Flags().StringVar(&toPeer, "to-peer", "", "when run on an active node, auto-select a peer by name or IP address (skips interactive prompt)")
	rootCmd.AddCommand(runCmd)
}

// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		// Fresh installations create the table from the current model first.
		_, err := db.ExecContext(ctx, "ALTER TABLE expected_switch ADD COLUMN IF NOT EXISTS nvos_ip_address TEXT")
		return err
	}, func(ctx context.Context, db *bun.DB) error {
		// Preserve stored addresses when rolling back the application.
		return nil
	})
}

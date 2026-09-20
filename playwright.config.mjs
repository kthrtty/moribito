import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  // 再試行はしない。不安定さは隠さず落とす。
  retries: 0,
  reporter: [['list']],
  use: { trace: 'off', video: 'off', screenshot: 'off' },
});

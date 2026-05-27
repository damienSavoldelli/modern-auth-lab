import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      include: ['assets/js/**/*.js'],
      provider: 'v8',
      reporter: ['text', 'lcov'],
    },
  },
});

import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["tests/**/*.test.ts"],
		environment: "node",
		globalSetup: ["tests/backend-setup.ts"],
		setupFiles: ["tests/setup.ts"],
	},
});

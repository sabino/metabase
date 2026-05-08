import fetchMock from "fetch-mock";
import { match } from "ts-pattern";

import {
  setupPropertiesEndpoints,
  setupSettingsEndpoints,
} from "__support__/server-mocks";
import { renderWithProviders, screen, waitFor } from "__support__/ui";
import {
  createMockSettingsState,
  createMockState,
} from "metabase/redux/store/mocks";
import type {
  EnterpriseSettingKey,
  EnterpriseSettingValue,
  SearchEngineSettingValue,
  SemanticEmbeddingProvider,
  SettingDefinition,
  TokenFeatures,
} from "metabase-types/api";
import {
  createMockSettings,
  createMockTokenFeatures,
  createMockUser,
} from "metabase-types/api/mocks";

import { SearchSettingsWidget } from "./SearchSettingsWidget";

const defaultMockSearchStatus = {
  indexed_count: 50,
  total_est: 100,
};

const settingDefinition = <Key extends EnterpriseSettingKey>(
  key: Key,
  value: EnterpriseSettingValue<Key>,
  description = `${key} setting`,
): SettingDefinition<Key> => ({
  key,
  value,
  is_env_setting: false,
  description,
  env_name: `MB_${key.toUpperCase().replaceAll("-", "_")}`,
});

const setup = async (
  searchEngine: SearchEngineSettingValue,
  plan: "pro" | "starter",
  searchStatusData = defaultMockSearchStatus,
  statusPollingInterval?: number,
  embeddingProvider: SemanticEmbeddingProvider = "openai-compatible",
) => {
  const tokenFeatures: Partial<TokenFeatures> = match(plan)
    .with("pro", () => ({
      semantic_search: true,
      hosting: true,
    }))
    .with("starter", () => ({
      hosting: true,
    }))
    .exhaustive();

  const settings = createMockSettings({
    "search-engine": searchEngine,
    "token-features": createMockTokenFeatures(tokenFeatures),
    "ee-embedding-provider": embeddingProvider,
    "ee-embedding-model": "custom-embedding-model",
    "ee-embedding-model-dimensions": 768,
    "llm-openai-compatible-api-base-url": "https://example.openai.azure.com/v1",
    "llm-openai-compatible-api-key": null,
  });

  setupPropertiesEndpoints(settings);
  setupSettingsEndpoints([
    settingDefinition("search-engine", searchEngine, "Search engine to use"),
    settingDefinition("ee-embedding-provider", embeddingProvider),
    settingDefinition("ee-embedding-model", "custom-embedding-model"),
    settingDefinition("ee-embedding-model-dimensions", 768),
    settingDefinition(
      "llm-openai-compatible-api-base-url",
      "https://example.openai.azure.com/v1",
    ),
    settingDefinition("llm-openai-compatible-api-key", null),
    settingDefinition("llm-openai-api-base-url", "https://api.openai.com"),
    settingDefinition("llm-openai-api-key", null),
    settingDefinition("ee-embedding-service-base-url", null),
    settingDefinition("ee-embedding-service-api-key", null),
  ]);

  // Mock the search status API
  fetchMock.get("path:/api/ee/semantic-search/status", searchStatusData, {
    name: "search-sync-status",
  });

  renderWithProviders(
    <SearchSettingsWidget statusPollingInterval={statusPollingInterval} />,
    {
      storeInitialState: createMockState({
        settings: createMockSettingsState(settings),
        currentUser: createMockUser({ is_superuser: true }),
      }),
    },
  );

  expect(
    await screen.findByTestId("search-engine-setting"),
  ).toBeInTheDocument();
};

const progressBar = () => screen.findByRole("progressbar");
const toggle = () => screen.findByRole("switch");

describe("SearchSettingsWidget", () => {
  it("should display upsell for non-pro plans", async () => {
    await setup("semantic", "starter");
    expect(
      await screen.findByText(/Advanced semantic search/),
    ).toBeInTheDocument();
    expect(await screen.findByText(/Get this with Pro/)).toBeInTheDocument();
  });

  it("should display setting toggle as disabled for pro plans", async () => {
    await setup("semantic", "pro");

    expect(
      await screen.findByText("Advanced semantic search"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("upsell-semantic-search"),
    ).not.toBeInTheDocument();
    expect(await toggle()).toBeDisabled();
    expect(await toggle()).toBeChecked();
  });

  it("should display embedding provider settings for pro plans", async () => {
    await setup("semantic", "pro");

    expect(
      await screen.findByLabelText("Embedding provider"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Embedding model")).toBeInTheDocument();
    expect(screen.getByLabelText("Embedding dimensions")).toBeInTheDocument();
    expect(
      screen.getByLabelText("OpenAI-compatible base URL"),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText("OpenAI-compatible API key"),
    ).toBeInTheDocument();
  });

  it("should display provider-specific settings for the official OpenAI provider", async () => {
    await setup(
      "semantic",
      "pro",
      defaultMockSearchStatus,
      undefined,
      "openai",
    );

    expect(await screen.findByLabelText("OpenAI base URL")).toBeInTheDocument();
    expect(screen.getByLabelText("OpenAI API key")).toBeInTheDocument();
    expect(
      screen.queryByLabelText("OpenAI-compatible base URL"),
    ).not.toBeInTheDocument();
  });

  it("should show progress when indexing is in progress", async () => {
    await setup("semantic", "pro", { indexed_count: 25, total_est: 100 });

    expect(
      await screen.findByText("Initializing search index..."),
    ).toBeInTheDocument();
    expect(await progressBar()).toHaveAttribute("aria-valuenow", "25");
  });

  it("should not show progress when once indexing is complete", async () => {
    await setup("semantic", "pro", { indexed_count: 50, total_est: 100 }, 50);

    expect(
      await screen.findByText("Initializing search index..."),
    ).toBeInTheDocument();
    expect(await progressBar()).toHaveAttribute("aria-valuenow", "50");

    fetchMock.modifyRoute("search-sync-status", {
      response: () => ({
        indexed_count: 100,
        total_est: 100,
      }),
    });
    expect(
      await screen.findByText(/Initialized search index/),
    ).toBeInTheDocument();
    expect(await progressBar()).toHaveAttribute("aria-valuenow", "100");
  });

  it("should not show progress when indexing was already complete", async () => {
    await setup("semantic", "pro", { indexed_count: 100, total_est: 100 });

    await waitFor(() => {
      expect(
        screen.queryByText("Initializing search index..."),
      ).not.toBeInTheDocument();
    });
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
  });

  it("should handle API errors", async () => {
    fetchMock.get("path:/api/ee/semantic-search/status", 500);
    await setup("semantic", "pro");

    expect(
      await screen.findByText("Unable to fetch health status of search index."),
    ).toBeInTheDocument();
  });
});

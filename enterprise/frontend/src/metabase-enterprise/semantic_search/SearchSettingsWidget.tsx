import { useEffect, useState } from "react";
import { t } from "ttag";
import _ from "underscore";

import { SettingHeader } from "metabase/admin/settings/components/SettingHeader";
import {
  AdminSettingInput,
  BasicAdminSettingInput,
} from "metabase/admin/settings/components/widgets/AdminSettingInput";
import { UpsellSemanticSearchPill } from "metabase/admin/upsells/UpsellSemanticSearch";
import { getErrorMessage, useAdminSetting } from "metabase/api/utils";
import { getPlan, isProPlan } from "metabase/common/utils/plan";
import type { SearchSettingsWidgetProps } from "metabase/plugins";
import { useSelector } from "metabase/redux";
import { getSetting } from "metabase/selectors/settings";
import { Box, Progress, Stack, Text, Tooltip } from "metabase/ui";
import { useGetSemanticSearchStatusQuery } from "metabase-enterprise/api/search";
import type { SemanticEmbeddingProvider } from "metabase-types/api";

function useLatch(bool: boolean) {
  const [hasSeenTrue, setHasSeenTrue] = useState(bool);

  useEffect(() => {
    if (bool && !hasSeenTrue) {
      setHasSeenTrue(true);
    }
  }, [hasSeenTrue, bool]);

  return hasSeenTrue;
}

function EmbeddingProviderSettings({
  provider,
}: {
  provider: SemanticEmbeddingProvider | null | undefined;
}) {
  if (provider === "openai-compatible") {
    return (
      <>
        <AdminSettingInput
          name="llm-openai-compatible-api-base-url"
          title={t`OpenAI-compatible base URL`}
          description={t`Base URL for a custom OpenAI-compatible API, such as an Azure OpenAI resource or a self-hosted gateway.`}
          placeholder="https://example.com/v1"
          inputType="text"
        />
        <AdminSettingInput
          name="llm-openai-compatible-api-key"
          title={t`OpenAI-compatible API key`}
          inputType="password"
        />
      </>
    );
  }

  if (provider === "openai") {
    return (
      <>
        <AdminSettingInput
          name="llm-openai-api-base-url"
          title={t`OpenAI base URL`}
          placeholder="https://api.openai.com"
          inputType="text"
        />
        <AdminSettingInput
          name="llm-openai-api-key"
          title={t`OpenAI API key`}
          inputType="password"
        />
      </>
    );
  }

  if (provider === "ai-service") {
    return (
      <>
        <AdminSettingInput
          name="ee-embedding-service-base-url"
          title={t`Embedding service base URL`}
          placeholder="https://example.com"
          inputType="text"
        />
        <AdminSettingInput
          name="ee-embedding-service-api-key"
          title={t`Embedding service API key`}
          inputType="password"
        />
      </>
    );
  }

  return null;
}

export function SearchSettingsWidget({
  statusPollingInterval = 5000,
}: SearchSettingsWidgetProps) {
  const plan = useSelector((state) =>
    getPlan(getSetting(state, "token-features")),
  );
  const shouldUpsell = !isProPlan(plan);

  const { value } = useAdminSetting("search-engine");
  const semanticSearchEnabled = value === "semantic";
  const { value: embeddingProvider } = useAdminSetting("ee-embedding-provider");
  const embeddingProviderOptions: {
    label: string;
    value: SemanticEmbeddingProvider;
  }[] = [
    { label: t`OpenAI-compatible`, value: "openai-compatible" },
    { label: t`OpenAI`, value: "openai" },
    { label: t`Embedding service`, value: "ai-service" },
    { label: t`Ollama`, value: "ollama" },
  ];

  const [hasFinishedIndexing, setHasFinishedIndexing] = useState(false);
  const response = useGetSemanticSearchStatusQuery(undefined, {
    pollingInterval: statusPollingInterval,
    skip: !semanticSearchEnabled || hasFinishedIndexing,
  });
  const { indexed_count = 0, total_est = 1 } = response.data || {};

  // total records is an estimate, assume we're done a bit early
  // to avoid showing status when we shouldn't
  const estimatedPercentComplete = Math.round(
    (indexed_count / total_est) * 100,
  );
  const progress =
    estimatedPercentComplete >= 95 ? 100 : estimatedPercentComplete;

  useEffect(() => {
    if (progress === 100) {
      setHasFinishedIndexing(true);
    }
  }, [progress]);

  const isIndexing = useLatch(response.data !== undefined && progress !== 100);

  return (
    <Stack data-testid="search-engine-setting">
      <Stack gap="0">
        <SettingHeader
          id="search-engine"
          title={t`Advanced semantic search`}
          description={t`Provides more relevant search results.`}
        />

        {shouldUpsell && (
          <div>
            <UpsellSemanticSearchPill source="settings-general" />
          </div>
        )}
      </Stack>

      {!shouldUpsell && (
        <>
          <Box>
            <Tooltip label={t`Contact support to change this setting.`}>
              <Box display="inline-flex">
                <BasicAdminSettingInput
                  name="search-engine"
                  inputType="boolean"
                  value={semanticSearchEnabled}
                  disabled
                  onChange={_.noop}
                />
              </Box>
            </Tooltip>
          </Box>

          {response.error && (
            <Text c="error">
              {getErrorMessage(
                response,
                t`Unable to fetch health status of search index.`,
              )}
            </Text>
          )}

          {!response.error && isIndexing && (
            <Stack gap="xs">
              <Progress
                size="md"
                value={progress}
                maw="25rem"
                animated={progress < 100}
              />
              <Text c="text-tertiary" size="md">
                {progress === 100
                  ? t`Initialized search index`
                  : t`Initializing search index...`}
              </Text>
            </Stack>
          )}

          <Stack gap="md" maw="38rem" mt="md">
            <AdminSettingInput
              name="ee-embedding-provider"
              title={t`Embedding provider`}
              description={t`Provider used to generate vectors for semantic search indexing and query matching.`}
              inputType="select"
              options={embeddingProviderOptions}
            />
            <AdminSettingInput
              name="ee-embedding-model"
              title={t`Embedding model`}
              inputType="text"
            />
            <AdminSettingInput
              name="ee-embedding-model-dimensions"
              title={t`Embedding dimensions`}
              inputType="number"
            />
            <EmbeddingProviderSettings
              provider={embeddingProvider as SemanticEmbeddingProvider | null}
            />
          </Stack>
        </>
      )}
    </Stack>
  );
}

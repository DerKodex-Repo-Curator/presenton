import { LLMConfig } from "@/types/llm_config";
import { hasValidLLMConfig, normalizeLLMConfig } from "@/utils/storeHelpers";
import { getFastApiBaseUrl, forwardedAuthHeaders } from "@/lib/fastapi-internal";

export const REDACTED_SECRET_PLACEHOLDER = "__configured__";
export type RuntimeProviderConfig = { configured: boolean; config: LLMConfig };

/** FastAPI returns an allowlisted, redacted view of its database settings. */
export async function readRuntimeProviderConfig(request: Request): Promise<RuntimeProviderConfig> {
  const response = await fetch(`${getFastApiBaseUrl()}/api/v1/config/runtime`, {
    headers: forwardedAuthHeaders(request), cache: "no-store",
  });
  if (!response.ok) throw new Error("Unable to read runtime configuration");
  const payload = await response.json();
  const config = normalizeLLMConfig(payload.config || {});
  return { configured: hasValidLLMConfig(config), config };
}

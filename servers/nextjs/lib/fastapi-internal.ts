import { DESKTOP_TOKEN_HEADER } from "@/lib/desktop-auth";

export function getFastApiBaseUrl(): string {
  return (process.env.FAST_API_INTERNAL_URL?.trim() || process.env.NEXT_PUBLIC_FAST_API?.trim() || "http://127.0.0.1:8000").replace(/\/+$/, "");
}

export function forwardedAuthHeaders(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie");
  const desktop = request.headers.get(DESKTOP_TOKEN_HEADER);
  return {
    ...(cookie ? { cookie } : {}),
    ...(desktop ? { [DESKTOP_TOKEN_HEADER]: desktop } : {}),
  };
}

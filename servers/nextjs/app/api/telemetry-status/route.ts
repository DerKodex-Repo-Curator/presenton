import { NextResponse } from "next/server";
import { getFastApiBaseUrl, forwardedAuthHeaders } from "@/lib/fastapi-internal";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const response = await fetch(`${getFastApiBaseUrl()}/api/v1/config/telemetry`, {
      headers: forwardedAuthHeaders(request), cache: "no-store",
    });
    if (!response.ok) throw new Error("Configuration service unavailable");
    const result = await response.json();
    return NextResponse.json({ telemetryEnabled: result.telemetryEnabled === true });
  } catch {
    // An unavailable configuration service must never enable tracking.
    return NextResponse.json({ telemetryEnabled: false });
  }
}

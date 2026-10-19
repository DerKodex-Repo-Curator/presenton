import { NextResponse } from "next/server";
import { readRuntimeProviderConfig } from "@/lib/runtime-provider-config";
import { authStatusForRequest } from "@/lib/server-auth-role";

export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  if (!(await authStatusForRequest(request)).authenticated) {
    return NextResponse.json({ detail: "Unauthorized" }, { status: 401 });
  }
  try {
    const { config } = await readRuntimeProviderConfig(request);
    return NextResponse.json({ hasKey: Boolean(config.OPENAI_API_KEY) });
  } catch {
    return NextResponse.json({ hasKey: false }, { status: 503 });
  }
}

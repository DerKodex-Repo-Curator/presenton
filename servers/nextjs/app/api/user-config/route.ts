import { NextResponse } from "next/server";
import { getFastApiBaseUrl } from "@/lib/fastapi-internal";
import {
  authStatusForRequest,
  requireAdminApi,
} from "@/lib/server-auth-role";
import { readRuntimeProviderConfig } from "@/lib/runtime-provider-config";
import { DESKTOP_TOKEN_HEADER } from "@/lib/desktop-auth";

async function forwardProviderSettings(
  request: Request,
  method: "GET" | "PUT",
  body?: string
) {
  const cookie = request.headers.get("cookie") || "";
  const response = await fetch(
    `${getFastApiBaseUrl()}/api/v1/admin/provider-settings`,
    {
      method,
      headers: {
        ...(cookie ? { cookie } : {}),
        ...(request.headers.get(DESKTOP_TOKEN_HEADER) ? { [DESKTOP_TOKEN_HEADER]: request.headers.get(DESKTOP_TOKEN_HEADER)! } : {}),
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body,
      cache: "no-store",
    }
  );
  const payload = await response.text();
  return new NextResponse(payload || null, {
    status: response.status,
    headers: {
      "content-type":
        response.headers.get("content-type") || "application/json",
    },
  });
}

export async function GET(request: Request) {
  const auth = await authStatusForRequest(request);
  if (!auth.authenticated) {
    return NextResponse.json({ detail: "Unauthorized" }, { status: 401 });
  }

  // Administrators need the real values in the settings forms. Regular users
  // only need the effective provider/model selection; shared secrets must
  // never be sent to their browser.
  if (auth.role !== "admin") {
    try {
      return NextResponse.json((await readRuntimeProviderConfig(request)).config);
    } catch {
      return NextResponse.json(
        { error: "Unable to read provider settings", status: 500 },
        { status: 500 }
      );
    }
  }

  try {
    return await forwardProviderSettings(request, "GET");
  } catch {
    return NextResponse.json(
      { error: "Unable to read provider settings", status: 500 },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await requireAdminApi(request);
  if (denied) return denied;
  if (request.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !== "application/json") {
    return NextResponse.json({ error: "Content-Type must be application/json" }, { status: 415 });
  }

  try {
    const body = await request.text();
    if (!body.trim()) {
      return NextResponse.json(
        { error: "Invalid user config JSON body", status: 400 },
        { status: 400 }
      );
    }
    const parsed = JSON.parse(body) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return NextResponse.json(
        { error: "Invalid user config JSON body", status: 400 },
        { status: 400 }
      );
    }
    return await forwardProviderSettings(request, "PUT", body);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return NextResponse.json(
        { error: "Invalid user config JSON body", status: 400 },
        { status: 400 }
      );
    }
    return NextResponse.json(
      { error: "Unable to save provider settings", status: 500 },
      { status: 500 }
    );
  }
}

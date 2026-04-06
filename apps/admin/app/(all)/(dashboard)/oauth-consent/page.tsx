/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { Shield, Check, X } from "lucide-react";
// plane imports
import { Button } from "@plane/propel/button";
// types
import type { Route } from "./+types/page";

interface IWorkspace {
  id: string;
  name: string;
  slug: string;
  logo: string;
}

const SCOPE_LABELS: Record<string, { label: string; description: string }> = {
  "read:projects": { label: "Read projects", description: "View your projects and their settings" },
  "write:projects": { label: "Write projects", description: "Create and modify projects" },
  "read:issues": { label: "Read issues", description: "View work items, comments, and activity" },
  "write:issues": { label: "Write issues", description: "Create, update, and delete work items" },
  "read:pages": { label: "Read pages", description: "View pages and their content" },
  "write:pages": { label: "Write pages", description: "Create and edit pages" },
  "read:cycles": { label: "Read cycles", description: "View cycles and their issues" },
  "write:cycles": { label: "Write cycles", description: "Create and modify cycles" },
  "read:modules": { label: "Read modules", description: "View modules and their issues" },
  "write:modules": { label: "Write modules", description: "Create and modify modules" },
  "read:members": { label: "Read members", description: "View workspace and project members" },
  admin: { label: "Full access", description: "Complete access to all workspace resources" },
};

function OAuthConsentPage(_props: Route.ComponentProps) {
  const [searchParams] = useSearchParams();
  const appName = searchParams.get("app_name") || "Unknown App";
  const scope = searchParams.get("scope") || "";
  const state = searchParams.get("state") || "";
  const clientId = searchParams.get("client_id") || "";

  const [workspaces, setWorkspaces] = useState<IWorkspace[]>([]);
  const [selectedWorkspace, setSelectedWorkspace] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const scopes = scope ? scope.split(" ").filter(Boolean) : [];

  useEffect(() => {
    // Fetch user's workspaces
    fetch("/api/instances/workspaces/", { credentials: "include" })
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data)) {
          setWorkspaces(data);
          if (data.length === 1) setSelectedWorkspace(data[0].id);
        }
      })
      .catch(() => {});
  }, []);

  const handleAuthorize = useCallback(async () => {
    if (!selectedWorkspace) return;
    setIsSubmitting(true);

    const formData = new URLSearchParams();
    formData.append("action", "approve");
    formData.append("workspace_id", selectedWorkspace);

    try {
      const response = await fetch("/auth/o/authorize-app/", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData.toString(),
        redirect: "manual",
      });

      // The server returns a redirect — follow it
      if (response.type === "opaqueredirect" || response.status === 302) {
        const location = response.headers.get("Location");
        if (location) {
          window.location.href = location;
          return;
        }
      }

      // If the response is a redirect, the browser will handle it
      if (response.redirected) {
        window.location.href = response.url;
        return;
      }

      // Fallback: try to parse as JSON error
      const data = await response.json();
      if (data.error) {
        alert(`Authorization failed: ${data.error_description || data.error}`);
      }
    } catch {
      alert("Authorization failed. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  }, [selectedWorkspace]);

  const handleDeny = useCallback(async () => {
    setIsSubmitting(true);

    const formData = new URLSearchParams();
    formData.append("action", "deny");

    try {
      const response = await fetch("/auth/o/authorize-app/", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData.toString(),
        redirect: "follow",
      });

      if (response.redirected) {
        window.location.href = response.url;
        return;
      }
    } catch {
      // Close the window if deny fails
      window.close();
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-layer-0 p-4">
      <div className="w-full max-w-md rounded-xl border border-subtle bg-layer-1 shadow-lg">
        {/* Header */}
        <div className="border-b border-subtle px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-accent-primary/10">
              <Shield className="h-5 w-5 text-accent-primary" />
            </div>
            <div>
              <div className="text-16 font-semibold">{appName}</div>
              <div className="text-12 text-tertiary">wants to access your Plane account</div>
            </div>
          </div>
        </div>

        {/* Scopes */}
        <div className="px-6 py-4 space-y-3">
          <div className="text-13 font-medium text-secondary">This app will be able to:</div>
          <div className="space-y-2">
            {scopes.map((s) => {
              const info = SCOPE_LABELS[s] || { label: s, description: "" };
              return (
                <div key={s} className="flex items-start gap-2">
                  <Check className="mt-0.5 h-4 w-4 shrink-0 text-green-500" />
                  <div>
                    <div className="text-13 font-medium">{info.label}</div>
                    {info.description && <div className="text-11 text-tertiary">{info.description}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Workspace selection */}
        <div className="border-t border-subtle px-6 py-4">
          <label className="text-13 font-medium text-secondary">Select workspace</label>
          <select
            className="mt-2 w-full rounded-md border border-subtle bg-layer-2 px-3 py-2 text-13"
            value={selectedWorkspace}
            onChange={(e) => setSelectedWorkspace(e.target.value)}
          >
            <option value="">Choose a workspace...</option>
            {workspaces.map((ws) => (
              <option key={ws.id} value={ws.id}>
                {ws.name}
              </option>
            ))}
          </select>
        </div>

        {/* Actions */}
        <div className="flex gap-3 border-t border-subtle px-6 py-4">
          <Button
            variant="primary"
            size="lg"
            className="flex-1"
            onClick={() => void handleAuthorize()}
            disabled={!selectedWorkspace || isSubmitting}
            loading={isSubmitting}
          >
            Authorize {appName}
          </Button>
          <Button variant="secondary" size="lg" onClick={() => void handleDeny()} disabled={isSubmitting}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* Footer */}
        <div className="rounded-b-xl bg-layer-2 px-6 py-3 text-center text-11 text-tertiary">
          Authorizing will share your account information with {appName}.
        </div>
      </div>
    </div>
  );
}

export const meta: Route.MetaFunction = () => [{ title: "Authorize Application - Plane" }];

export default OAuthConsentPage;

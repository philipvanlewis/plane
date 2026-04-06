/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useCallback, useState } from "react";
import useSWR from "swr";
import { Plus, Copy, Trash2, RefreshCw, KeyRound } from "lucide-react";
// plane imports
import { Button } from "@plane/propel/button";
import { TOAST_TYPE, setToast } from "@plane/propel/toast";
// components
import { PageWrapper } from "@/components/common/page-wrapper";
// types
import type { Route } from "./+types/page";

interface IOAuthApp {
  id: string;
  name: string;
  description: string;
  client_id: string;
  redirect_uris: string[];
  homepage_url: string;
  logo_url: string;
  is_active: boolean;
  allowed_scopes: string[];
  created_at: string;
  updated_at: string;
  created_by: string;
}

const API_BASE = "/api/instances";

async function fetchOAuthApps(): Promise<IOAuthApp[]> {
  const response = await fetch(`${API_BASE}/oauth-apps/`, { credentials: "include" });
  if (!response.ok) throw new Error("Failed to fetch OAuth apps");
  return response.json();
}

async function createOAuthApp(data: Partial<IOAuthApp>): Promise<IOAuthApp & { client_secret: string }> {
  const response = await fetch(`${API_BASE}/oauth-apps/`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error || "Failed to create OAuth app");
  }
  return response.json();
}

async function deleteOAuthApp(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/oauth-apps/${id}/`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!response.ok) throw new Error("Failed to delete OAuth app");
}

async function regenerateSecret(id: string): Promise<{ client_secret: string }> {
  const response = await fetch(`${API_BASE}/oauth-apps/${id}/regenerate-secret/`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) throw new Error("Failed to regenerate secret");
  return response.json();
}

function OAuthAppsPage(_props: Route.ComponentProps) {
  const { data: apps, mutate } = useSWR("OAUTH_APPS", fetchOAuthApps);
  const [showCreate, setShowCreate] = useState(false);
  const [newAppName, setNewAppName] = useState("");
  const [newAppDescription, setNewAppDescription] = useState("");
  const [newAppRedirectUri, setNewAppRedirectUri] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState<{ appId: string; secret: string } | null>(null);

  const handleCreate = useCallback(async () => {
    if (!newAppName.trim()) return;
    setIsCreating(true);
    try {
      const result = await createOAuthApp({
        name: newAppName.trim(),
        description: newAppDescription.trim(),
        redirect_uris: newAppRedirectUri.trim() ? [newAppRedirectUri.trim()] : [],
      });
      setRevealedSecret({ appId: result.id, secret: result.client_secret });
      setNewAppName("");
      setNewAppDescription("");
      setNewAppRedirectUri("");
      setShowCreate(false);
      void mutate();
      setToast({ type: TOAST_TYPE.SUCCESS, title: "App created", message: "Copy the client secret now — it won't be shown again." });
    } catch (err) {
      setToast({ type: TOAST_TYPE.ERROR, title: "Error", message: err instanceof Error ? err.message : "Failed to create app" });
    } finally {
      setIsCreating(false);
    }
  }, [newAppName, newAppDescription, newAppRedirectUri, mutate]);

  const handleDelete = useCallback(async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This will revoke all tokens and remove all installations.`)) return;
    try {
      await deleteOAuthApp(id);
      void mutate();
      setToast({ type: TOAST_TYPE.SUCCESS, title: "Deleted", message: `${name} has been deleted.` });
    } catch {
      setToast({ type: TOAST_TYPE.ERROR, title: "Error", message: "Failed to delete app" });
    }
  }, [mutate]);

  const handleRegenerate = useCallback(async (id: string, name: string) => {
    if (!confirm(`Regenerate secret for "${name}"? This will revoke ALL active tokens.`)) return;
    try {
      const result = await regenerateSecret(id);
      setRevealedSecret({ appId: id, secret: result.client_secret });
      setToast({ type: TOAST_TYPE.SUCCESS, title: "Secret regenerated", message: "Copy the new secret now. All existing tokens have been revoked." });
    } catch {
      setToast({ type: TOAST_TYPE.ERROR, title: "Error", message: "Failed to regenerate secret" });
    }
  }, []);

  const copyToClipboard = useCallback((text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    setToast({ type: TOAST_TYPE.SUCCESS, title: "Copied", message: `${label} copied to clipboard.` });
  }, []);

  return (
    <PageWrapper
      header={{
        title: "OAuth Applications",
        description: "Register and manage OAuth apps that can authenticate Plane users.",
      }}
    >
      <div className="space-y-6">
        {/* Create button */}
        <div className="flex justify-end">
          <Button variant="primary" size="sm" onClick={() => setShowCreate(!showCreate)}>
            <Plus className="h-4 w-4 mr-1" />
            Register new app
          </Button>
        </div>

        {/* Create form */}
        {showCreate && (
          <div className="rounded-lg border border-subtle bg-layer-2 p-6 space-y-4">
            <div className="text-16 font-medium">Register a new OAuth application</div>
            <div className="space-y-3">
              <div>
                <label className="text-13 font-medium text-secondary">Application name *</label>
                <input
                  type="text"
                  className="mt-1 w-full rounded-md border border-subtle bg-layer-1 px-3 py-2 text-13"
                  placeholder="My MCP Server"
                  value={newAppName}
                  onChange={(e) => setNewAppName(e.target.value)}
                />
              </div>
              <div>
                <label className="text-13 font-medium text-secondary">Description</label>
                <input
                  type="text"
                  className="mt-1 w-full rounded-md border border-subtle bg-layer-1 px-3 py-2 text-13"
                  placeholder="Optional description"
                  value={newAppDescription}
                  onChange={(e) => setNewAppDescription(e.target.value)}
                />
              </div>
              <div>
                <label className="text-13 font-medium text-secondary">Redirect URI</label>
                <input
                  type="text"
                  className="mt-1 w-full rounded-md border border-subtle bg-layer-1 px-3 py-2 text-13"
                  placeholder="https://example.com/callback"
                  value={newAppRedirectUri}
                  onChange={(e) => setNewAppRedirectUri(e.target.value)}
                />
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <Button variant="primary" size="sm" onClick={() => void handleCreate()} loading={isCreating} disabled={!newAppName.trim()}>
                Create
              </Button>
              <Button variant="secondary" size="sm" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Secret reveal banner */}
        {revealedSecret && (
          <div className="rounded-lg border border-accent-primary/30 bg-accent-primary/5 p-4 space-y-2">
            <div className="flex items-center gap-2 text-14 font-medium text-accent-primary">
              <KeyRound className="h-4 w-4" />
              Client Secret (copy now — this won't be shown again)
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded bg-layer-3 px-3 py-2 text-12 font-mono break-all">
                {revealedSecret.secret}
              </code>
              <button
                className="shrink-0 rounded p-2 hover:bg-layer-3"
                onClick={() => copyToClipboard(revealedSecret.secret, "Client secret")}
              >
                <Copy className="h-4 w-4 text-secondary" />
              </button>
            </div>
            <button className="text-12 text-secondary hover:text-primary" onClick={() => setRevealedSecret(null)}>
              Dismiss
            </button>
          </div>
        )}

        {/* Apps list */}
        {apps === undefined ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-20 animate-pulse rounded-lg bg-layer-2" />
            ))}
          </div>
        ) : apps.length === 0 ? (
          <div className="rounded-lg border border-subtle bg-layer-2 p-8 text-center">
            <KeyRound className="mx-auto h-8 w-8 text-tertiary" />
            <div className="mt-3 text-14 font-medium text-secondary">No OAuth apps registered</div>
            <div className="mt-1 text-12 text-tertiary">
              Register an OAuth app to enable third-party tools to authenticate Plane users.
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {apps.map((app) => (
              <div key={app.id} className="flex items-center gap-4 rounded-lg border border-subtle bg-layer-2 px-4 py-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-14 font-medium truncate">{app.name}</span>
                    {!app.is_active && (
                      <span className="rounded-full bg-red-500/10 px-2 py-0.5 text-10 font-medium text-red-500">
                        Inactive
                      </span>
                    )}
                  </div>
                  {app.description && (
                    <div className="text-12 text-tertiary truncate">{app.description}</div>
                  )}
                  <div className="mt-1 flex items-center gap-3 text-11 text-tertiary">
                    <span className="font-mono">{app.client_id}</span>
                    <button
                      className="hover:text-primary"
                      onClick={() => copyToClipboard(app.client_id, "Client ID")}
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                    {app.redirect_uris.length > 0 && (
                      <span>{app.redirect_uris.length} redirect URI{app.redirect_uris.length > 1 ? "s" : ""}</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    className="rounded p-1.5 text-secondary hover:bg-layer-3 hover:text-primary"
                    onClick={() => void handleRegenerate(app.id, app.name)}
                    title="Regenerate secret"
                  >
                    <RefreshCw className="h-4 w-4" />
                  </button>
                  <button
                    className="rounded p-1.5 text-secondary hover:bg-red-500/10 hover:text-red-500"
                    onClick={() => void handleDelete(app.id, app.name)}
                    title="Delete app"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </PageWrapper>
  );
}

export const meta: Route.MetaFunction = () => [{ title: "OAuth Apps - Plane Admin" }];

export default OAuthAppsPage;

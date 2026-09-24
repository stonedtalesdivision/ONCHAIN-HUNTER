const API = "https://api.github.com";
export type GitHubFile = { path: string; type: string; size?: number; download_url?: string };
export async function listRepositoryFiles(repository: string, token?: string): Promise<GitHubFile[]> {
  const [owner, name] = repository.split("/");
  if (!owner || !name) throw new Error("Invalid repository: " + repository);
  const headers: Record<string,string> = { accept: "application/vnd.github+json", "x-github-api-version": "2026-03-10", "user-agent": "ONCHAIN-HUNTER/0.3" };
  if (token) headers.authorization = "Bearer " + token;
  const meta = await fetch(API + "/repos/" + owner + "/" + name, { headers });
  if (!meta.ok) throw new Error("GitHub repository lookup failed: HTTP " + meta.status);
  const repoMeta = await meta.json() as { default_branch: string };
  const tree = await fetch(API + "/repos/" + owner + "/" + name + "/git/trees/" + encodeURIComponent(repoMeta.default_branch) + "?recursive=1", { headers });
  if (!tree.ok) throw new Error("GitHub tree lookup failed: HTTP " + tree.status);
  const data = await tree.json() as { tree?: Array<{ path: string; type: string; size?: number }>; truncated?: boolean };
  if (data.truncated) throw new Error("Repository tree is truncated; refusing incomplete scan");
  return (data.tree ?? []).filter(x => x.type === "blob").map(x => ({ ...x, download_url: "https://raw.githubusercontent.com/" + repository + "/" + repoMeta.default_branch + "/" + x.path }));
}
export async function fetchRawFile(url: string, token?: string): Promise<string> {
  const headers: Record<string,string> = { "user-agent": "ONCHAIN-HUNTER/0.3" };
  if (token) headers.authorization = "Bearer " + token;
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error("GitHub file fetch failed: HTTP " + r.status);
  return r.text();
}

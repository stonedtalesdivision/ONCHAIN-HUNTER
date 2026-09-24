const API = "https://api.github.com";
export type GitHubFile = { path: string; type: string; size?: number; download_url?: string };
export type GitHubRevision = { requestedRef: string; commitSha: string; treeSha: string };

function headers(token?: string): Record<string,string> {
  const h: Record<string,string> = { accept: "application/vnd.github+json", "x-github-api-version": "2026-03-10", "user-agent": "ONCHAIN-HUNTER/0.4" };
  if (token) h.authorization = "Bearer " + token;
  return h;
}

function splitRepository(repository: string): [string,string] {
  const [owner, name] = repository.split("/");
  if (!owner || !name) throw new Error("Invalid repository: " + repository);
  return [owner, name];
}

export async function resolveRepositoryRevision(repository: string, ref: string, token?: string): Promise<GitHubRevision> {
  const [owner, name] = splitRepository(repository);
  const h = headers(token);
  const commit = await fetch(API + "/repos/" + owner + "/" + name + "/commits/" + encodeURIComponent(ref), { headers: h });
  if (!commit.ok) throw new Error("GitHub revision lookup failed for " + ref + ": HTTP " + commit.status);
  const commitData = await commit.json() as { sha?: string };
  if (!commitData.sha) throw new Error("GitHub revision lookup returned no commit SHA");

  const commitObject = await fetch(API + "/repos/" + owner + "/" + name + "/git/commits/" + commitData.sha, { headers: h });
  if (!commitObject.ok) throw new Error("GitHub git commit lookup failed: HTTP " + commitObject.status);
  const commitPayload = await commitObject.json() as { tree?: { sha?: string } };
  const treeSha = commitPayload.tree?.sha;
  if (!treeSha) throw new Error("GitHub git commit returned no tree SHA");
  return { requestedRef: ref, commitSha: commitData.sha, treeSha };
}

export async function listRepositoryFiles(repository: string, token?: string, ref?: string): Promise<GitHubFile[]> {
  const [owner, name] = splitRepository(repository);
  const h = headers(token);
  let requestedRef = ref;
  if (!requestedRef) {
    const meta = await fetch(API + "/repos/" + owner + "/" + name, { headers: h });
    if (!meta.ok) throw new Error("GitHub repository lookup failed: HTTP " + meta.status);
    const repoMeta = await meta.json() as { default_branch: string };
    requestedRef = repoMeta.default_branch;
  }
  const revision = await resolveRepositoryRevision(repository, requestedRef, token);
  const tree = await fetch(API + "/repos/" + owner + "/" + name + "/git/trees/" + revision.treeSha + "?recursive=1", { headers: h });
  if (!tree.ok) throw new Error("GitHub tree lookup failed: HTTP " + tree.status);
  const data = await tree.json() as { tree?: Array<{ path: string; type: string; size?: number }>; truncated?: boolean };
  if (data.truncated) throw new Error("Repository tree is truncated; refusing incomplete scan");
  return (data.tree ?? []).filter(x => x.type === "blob").map(x => ({
    ...x,
    download_url: "https://raw.githubusercontent.com/" + repository + "/" + revision.commitSha + "/" + x.path
  }));
}

export async function fetchRawFile(url: string, token?: string): Promise<string> {
  const h: Record<string,string> = { "user-agent": "ONCHAIN-HUNTER/0.4" };
  if (token) h.authorization = "Bearer " + token;
  const r = await fetch(url, { headers: h });
  if (!r.ok) throw new Error("GitHub file fetch failed: HTTP " + r.status);
  return r.text();
}

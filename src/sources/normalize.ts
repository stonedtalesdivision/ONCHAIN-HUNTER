const URL_RE = /https?:\/\/[^\s)\]}>,]+/gi;
const GITHUB_RE = /^https?:\/\/github\.com\/([^/]+\/[^/#?]+)(?:\/.*)?$/i;

export function extractUrls(values: string[]): string[] {
  return [...new Set(values.flatMap(v => v.match(URL_RE) ?? []).map(v => v.replace(/[.,;:]+$/, "")))];
}

export function extractGitHubRepos(values: string[]): string[] {
  return [...new Set(extractUrls(values).flatMap(url => {
    const match = url.match(GITHUB_RE);
    return match ? [match[1].replace(/\.git$/i, "")] : [];
  }))];
}

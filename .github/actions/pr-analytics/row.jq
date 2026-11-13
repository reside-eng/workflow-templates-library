# Copy of workflow-templates .github/actions/pr-analytics/row.jq (the unit tests live there): keep the two files identical below this line.
# Row of side-dw.github.pull_requests for one closed pull request (AI v2 M1 PLAT-12247, M2 PLAT-12248).
# Inputs: $pr (GET pulls/N), $reviews, $commit_authors, $recorded_at, $repository, $source, $run_id.
# Metadata only. The title and the body are read to derive the facts below and are never stored.

def title: ($pr.title // "");
def body: ($pr.body // "");
def head_ref: ($pr.head.ref // "");

# The PR undoes earlier work: a revert title (conventional type `revert`, a subject starting with "revert", GitHub's `Revert "..."`),
# the branch of GitHub's revert button, or a body that says what it reverts.
def is_revert:
  (title | test("^revert\\b"; "i"))
  or (title | test("^[a-z]+(\\([^)]*\\))?!?:\\s*revert(s|ed)?\\b"; "i"))
  or (title | test("\\bRevert \""))
  or (head_ref | test("^revert-[0-9]+-"))
  or (body | test("This reverts commit [0-9a-f]{7,40}"))
  or (body | test("\\bReverts ([\\w./-]+)?#[0-9]+"));

# PR numbers the revert names: the revert branch, then every #N, /pull/N or "PR N" on the first body lines that say revert.
# Only earlier PRs of the repository qualify; the join on the repository happens in BigQuery (view kr_reverts).
def reverts_numbers:
  ( [head_ref | capture("^revert-(?<n>[0-9]+)-") | .n | tonumber]
  + [ [body | split("\n")[] | select(test("\\brevert(s|ed|ing)?\\b"; "i"))][:5][]
      | scan("(?:#|/pull/|\\bPR #?)([0-9]+)") | .[0] | tonumber ] )
  | map(select(. < $pr.number)) | unique | .[:20];

def reverts_sha: [body | capture("This reverts commit (?<s>[0-9a-f]{40})") | .s][0];

# Conventional-commit type of the title, lower case: feat, fix, chore, revert, ...
def title_type: [title | capture("^(?<t>[A-Za-z]+)(\\([^)]*\\))?!?:") | .t | ascii_downcase][0];

{
  recorded_at: $recorded_at, repository: $repository, number: $pr.number,
  author: $pr.user.login, author_type: $pr.user.type, state: $pr.state, merged: ($pr.merged == true),
  created_at: $pr.created_at, closed_at: $pr.closed_at, merged_at: $pr.merged_at,
  merged_by: ($pr.merged_by.login // null),
  base_ref: $pr.base.ref, head_ref: $pr.head.ref, head_sha: $pr.head.sha, merge_commit_sha: $pr.merge_commit_sha,
  draft: ($pr.draft == true), labels: [$pr.labels[].name],
  additions: $pr.additions, deletions: $pr.deletions, changed_files: $pr.changed_files, commits: $pr.commits,
  auto_merge: ($pr.auto_merge != null), auto_merge_by: ($pr.auto_merge.enabled_by.login // null),
  reviews: $reviews, review_comments: $pr.review_comments, comments: $pr.comments,
  source: $source, run_id: $run_id,
  is_revert: is_revert,
  reverts_numbers: (if is_revert then reverts_numbers else [] end),
  reverts_sha: (if is_revert then reverts_sha else null end),
  title_type: title_type,
  commit_authors: $commit_authors
}

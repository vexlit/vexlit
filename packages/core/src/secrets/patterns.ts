import type { Severity, Confidence } from "../types.js";

export interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  owasp: string;
}

// ---------- Cloud Providers ----------
const cloud: SecretPattern[] = [
  { id: "AWS_ACCESS_KEY", name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "AWS_SECRET_KEY", name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*["'`][A-Za-z0-9/+=]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "AWS_MWS_KEY", name: "AWS MWS Key", pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GCP_API_KEY", name: "Google Cloud API Key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GCP_SERVICE_ACCOUNT", name: "Google Service Account", pattern: /"type"\s*:\s*"service_account"/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GCP_OAUTH_ID", name: "Google OAuth Client ID", pattern: /[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "AZURE_SUB_KEY", name: "Azure Subscription Key", pattern: /(?:azure[_-]?(?:subscription|api)[_-]?key)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "AZURE_CONNECTION", name: "Azure Connection String", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,88}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "AZURE_SAS_TOKEN", name: "Azure SAS Token", pattern: /[?&]sig=[A-Za-z0-9%+/=]{43,}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "ALIBABA_ACCESS_KEY", name: "Alibaba Cloud Access Key", pattern: /\bLTAI[0-9A-Za-z]{20}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "IBM_CLOUD_KEY", name: "IBM Cloud API Key", pattern: /(?:ibm[_-]?cloud[_-]?api[_-]?key)\s*[:=]\s*["'`][A-Za-z0-9_-]{44}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DIGITALOCEAN_TOKEN", name: "DigitalOcean Access Token", pattern: /\bdop_v1_[0-9a-f]{64}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DIGITALOCEAN_PAT", name: "DigitalOcean Personal Access Token", pattern: /\bdoctl[_-]?(?:access[_-]?)?token\s*[:=]\s*["'`][0-9a-f]{64}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "HEROKU_API_KEY", name: "Heroku API Key", pattern: /(?:heroku[_-]?api[_-]?key)\s*[:=]\s*["'`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CLOUDFLARE_API_KEY", name: "Cloudflare API Key", pattern: /(?:cloudflare[_-]?api[_-]?key)\s*[:=]\s*["'`][0-9a-f]{37}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CLOUDFLARE_TOKEN", name: "Cloudflare API Token", pattern: /(?:cloudflare[_-]?(?:api[_-]?)?token)\s*[:=]\s*["'`][A-Za-z0-9_-]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "VERCEL_TOKEN", name: "Vercel Token", pattern: /(?:vercel[_-]?token)\s*[:=]\s*["'`][A-Za-z0-9]{24}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "NETLIFY_TOKEN", name: "Netlify Access Token", pattern: /(?:netlify[_-]?(?:access[_-]?)?token)\s*[:=]\s*["'`][A-Za-z0-9_-]{40,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SUPABASE_KEY", name: "Supabase Service Role Key", pattern: /\beyJ[A-Za-z0-9_-]{100,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Payment & Finance ----------
const payment: SecretPattern[] = [
  { id: "STRIPE_SECRET", name: "Stripe Secret Key", pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "STRIPE_RESTRICTED", name: "Stripe Restricted Key", pattern: /\brk_live_[0-9a-zA-Z]{24,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "STRIPE_PUBLISHABLE", name: "Stripe Publishable Key (live)", pattern: /\bpk_live_[0-9a-zA-Z]{24,}\b/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "STRIPE_WEBHOOK", name: "Stripe Webhook Secret", pattern: /\bwhsec_[0-9a-zA-Z]{24,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SQUARE_ACCESS", name: "Square Access Token", pattern: /\bsq0atp-[0-9A-Za-z_-]{22}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SQUARE_OAUTH", name: "Square OAuth Secret", pattern: /\bsq0csp-[0-9A-Za-z_-]{43}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "PAYPAL_BRAINTREE", name: "PayPal Braintree Access Token", pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "PLAID_SECRET", name: "Plaid Secret Key", pattern: /(?:plaid[_-]?secret)\s*[:=]\s*["'`][0-9a-f]{30}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "COINBASE_KEY", name: "Coinbase API Key", pattern: /(?:coinbase[_-]?api[_-]?(?:key|secret))\s*[:=]\s*["'`][A-Za-z0-9]{16,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Communication ----------
const communication: SecretPattern[] = [
  { id: "TWILIO_API_KEY", name: "Twilio API Key", pattern: /\bSK[0-9a-fA-F]{32}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TWILIO_ACCOUNT_SID", name: "Twilio Account SID", pattern: /\bAC[0-9a-f]{32}\b/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TWILIO_AUTH_TOKEN", name: "Twilio Auth Token", pattern: /(?:twilio[_-]?auth[_-]?token)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SENDGRID_API_KEY", name: "SendGrid API Key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "MAILGUN_API_KEY", name: "Mailgun API Key", pattern: /\bkey-[0-9a-zA-Z]{32}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "MAILCHIMP_API_KEY", name: "Mailchimp API Key", pattern: /[0-9a-f]{32}-us[0-9]{1,2}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "POSTMARK_TOKEN", name: "Postmark Server Token", pattern: /(?:postmark[_-]?(?:server[_-]?)?token)\s*[:=]\s*["'`][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "RESEND_KEY", name: "Resend API Key", pattern: /\bre_[0-9a-zA-Z]{20,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Chat & Collaboration ----------
const chat: SecretPattern[] = [
  { id: "SLACK_TOKEN", name: "Slack Bot/User Token", pattern: /\bxox[bpas]-[0-9]{10,}-[0-9a-zA-Z]{10,}/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SLACK_WEBHOOK", name: "Slack Webhook URL", pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DISCORD_TOKEN", name: "Discord Bot Token", pattern: /(?:discord[_-]?(?:bot[_-]?)?token)\s*[:=]\s*["'`][A-Za-z0-9._-]{59,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DISCORD_WEBHOOK", name: "Discord Webhook URL", pattern: /https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TELEGRAM_TOKEN", name: "Telegram Bot Token", pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TEAMS_WEBHOOK", name: "Microsoft Teams Webhook", pattern: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[0-9a-f-]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- VCS / DevOps ----------
const vcs: SecretPattern[] = [
  { id: "GITHUB_PAT", name: "GitHub Personal Access Token", pattern: /\bghp_[A-Za-z0-9]{36}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITHUB_OAUTH", name: "GitHub OAuth Access Token", pattern: /\bgho_[A-Za-z0-9]{36}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITHUB_USER_TO_SERVER", name: "GitHub User-to-Server Token", pattern: /\bghu_[A-Za-z0-9]{36}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITHUB_SERVER_TO_SERVER", name: "GitHub Server-to-Server Token", pattern: /\bghs_[A-Za-z0-9]{36}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITHUB_REFRESH", name: "GitHub Refresh Token", pattern: /\bghr_[A-Za-z0-9]{36}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITHUB_FINE_GRAINED", name: "GitHub Fine-grained PAT", pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITLAB_PAT", name: "GitLab Personal Access Token", pattern: /\bglpat-[0-9A-Za-z_-]{20}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITLAB_PIPELINE", name: "GitLab Pipeline Token", pattern: /\bglptt-[0-9a-f]{40}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GITLAB_RUNNER", name: "GitLab Runner Registration Token", pattern: /\bGR1348941[0-9A-Za-z_-]{20}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "BITBUCKET_APP_PW", name: "Bitbucket App Password", pattern: /(?:bitbucket[_-]?(?:app[_-]?)?password)\s*[:=]\s*["'`][A-Za-z0-9]{18,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CIRCLECI_TOKEN", name: "CircleCI Token", pattern: /(?:circleci[_-]?token)\s*[:=]\s*["'`][0-9a-f]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TRAVIS_TOKEN", name: "Travis CI Token", pattern: /(?:travis[_-]?(?:ci[_-]?)?token)\s*[:=]\s*["'`][A-Za-z0-9]{22}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "JENKINS_TOKEN", name: "Jenkins API Token", pattern: /(?:jenkins[_-]?(?:api[_-]?)?token)\s*[:=]\s*["'`][0-9a-f]{32,34}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "NPM_TOKEN", name: "npm Access Token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "PYPI_TOKEN", name: "PyPI API Token", pattern: /\bpypi-[A-Za-z0-9_-]{100,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DOCKER_TOKEN", name: "Docker Access Token", pattern: /\bdckr_pat_[A-Za-z0-9_-]{27}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- AI / ML ----------
const ai: SecretPattern[] = [
  { id: "OPENAI_API_KEY", name: "OpenAI API Key", pattern: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "OPENAI_PROJECT_KEY", name: "OpenAI Project Key", pattern: /\bsk-proj-[A-Za-z0-9_-]{40,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "ANTHROPIC_API_KEY", name: "Anthropic API Key", pattern: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "COHERE_API_KEY", name: "Cohere API Key", pattern: /(?:cohere[_-]?api[_-]?key)\s*[:=]\s*["'`][A-Za-z0-9]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "HUGGINGFACE_TOKEN", name: "Hugging Face Token", pattern: /\bhf_[A-Za-z0-9]{34}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "REPLICATE_TOKEN", name: "Replicate API Token", pattern: /\br8_[A-Za-z0-9]{37}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TOGETHER_API_KEY", name: "Together AI API Key", pattern: /(?:together[_-]?api[_-]?key)\s*[:=]\s*["'`][0-9a-f]{64}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Database ----------
const database: SecretPattern[] = [
  { id: "MONGO_URI", name: "MongoDB Connection String", pattern: /mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^/\s]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "POSTGRES_URI", name: "PostgreSQL Connection String", pattern: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^/\s]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "MYSQL_URI", name: "MySQL Connection String", pattern: /mysql:\/\/[^:\s]+:[^@\s]+@[^/\s]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "REDIS_URI", name: "Redis Connection String", pattern: /redis(?:s)?:\/\/[^:\s]*:[^@\s]+@[^/\s]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "FIREBASE_PRIVATE_KEY", name: "Firebase Private Key", pattern: /(?:firebase[_-]?private[_-]?key)\s*[:=]\s*["'`]-----BEGIN/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "FIREBASE_API_KEY", name: "Firebase API Key", pattern: /(?:firebase[_-]?api[_-]?key)\s*[:=]\s*["'`]AIza[0-9A-Za-z_-]{35}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "ELASTICSEARCH_URI", name: "Elasticsearch Credentials", pattern: /https?:\/\/[^:\s]+:[^@\s]+@[^/\s]*(?:elastic|es)[^/\s]*/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Auth / SSO ----------
const auth: SecretPattern[] = [
  { id: "AUTH0_SECRET", name: "Auth0 Client Secret", pattern: /(?:auth0[_-]?client[_-]?secret)\s*[:=]\s*["'`][A-Za-z0-9_-]{30,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "OKTA_TOKEN", name: "Okta API Token", pattern: /(?:okta[_-]?(?:api[_-]?)?token)\s*[:=]\s*["'`]00[A-Za-z0-9_-]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CLERK_SECRET", name: "Clerk Secret Key", pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SUPABASE_SERVICE_KEY", name: "Supabase Service Role Key", pattern: /(?:supabase[_-]?service[_-]?(?:role[_-]?)?key)\s*[:=]\s*["'`]eyJ[A-Za-z0-9_-]+["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "OAUTH_CLIENT_SECRET", name: "OAuth Client Secret", pattern: /(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*["'`][A-Za-z0-9_-]{24,}["'`]/i, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Monitoring / Analytics ----------
const monitoring: SecretPattern[] = [
  { id: "SENTRY_DSN", name: "Sentry DSN", pattern: /https:\/\/[0-9a-f]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DATADOG_API_KEY", name: "Datadog API Key", pattern: /(?:datadog[_-]?api[_-]?key)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "DATADOG_APP_KEY", name: "Datadog Application Key", pattern: /(?:datadog[_-]?app(?:lication)?[_-]?key)\s*[:=]\s*["'`][0-9a-f]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "NEWRELIC_KEY", name: "New Relic API Key", pattern: /\bNRAK-[A-Z0-9]{27}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "NEWRELIC_LICENSE", name: "New Relic License Key", pattern: /(?:new[_-]?relic[_-]?license[_-]?key)\s*[:=]\s*["'`][0-9a-f]{40}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "PAGERDUTY_KEY", name: "PagerDuty API Key", pattern: /(?:pagerduty[_-]?(?:api[_-]?)?key)\s*[:=]\s*["'`][A-Za-z0-9+/=_-]{20}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SEGMENT_KEY", name: "Segment Write Key", pattern: /(?:segment[_-]?(?:write[_-]?)?key)\s*[:=]\s*["'`][A-Za-z0-9]{32}["'`]/i, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "MIXPANEL_TOKEN", name: "Mixpanel Project Token", pattern: /(?:mixpanel[_-]?(?:project[_-]?)?token)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "AMPLITUDE_KEY", name: "Amplitude API Key", pattern: /(?:amplitude[_-]?(?:api[_-]?)?key)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "LOGROCKET_KEY", name: "LogRocket App ID", pattern: /(?:logrocket[_-]?(?:app[_-]?)?id)\s*[:=]\s*["'`][a-z0-9]{6}\/[a-z0-9-]+["'`]/i, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Storage / CDN ----------
const storage: SecretPattern[] = [
  { id: "S3_BUCKET_URL", name: "AWS S3 Bucket with Credentials", pattern: /https?:\/\/[^:\s]+:[^@\s]+@s3[.-]/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CLOUDINARY_URL", name: "Cloudinary URL", pattern: /cloudinary:\/\/[0-9]+:[A-Za-z0-9_-]+@[A-Za-z0-9_-]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CLOUDINARY_KEY", name: "Cloudinary API Secret", pattern: /(?:cloudinary[_-]?(?:api[_-]?)?secret)\s*[:=]\s*["'`][A-Za-z0-9_-]{20,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "UPLOADTHING_SECRET", name: "UploadThing Secret", pattern: /\bsk_live_[A-Za-z0-9]{48,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- CMS / Content ----------
const cms: SecretPattern[] = [
  { id: "CONTENTFUL_TOKEN", name: "Contentful Access Token", pattern: /(?:contentful[_-]?(?:access[_-]?)?token)\s*[:=]\s*["'`][A-Za-z0-9_-]{43,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SANITY_TOKEN", name: "Sanity API Token", pattern: /(?:sanity[_-]?(?:api[_-]?)?token)\s*[:=]\s*["'`]sk[A-Za-z0-9]{80,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "STRAPI_TOKEN", name: "Strapi API Token", pattern: /(?:strapi[_-]?(?:api[_-]?)?token)\s*[:=]\s*["'`][0-9a-f]{64,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "WORDPRESS_KEY", name: "WordPress Auth Key", pattern: /define\(\s*["'](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)["']\s*,\s*["'][^"']{20,}["']\s*\)/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Maps / Location ----------
const maps: SecretPattern[] = [
  { id: "GOOGLE_MAPS_KEY", name: "Google Maps API Key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "MAPBOX_TOKEN", name: "Mapbox Access Token", pattern: /\bpk\.[a-zA-Z0-9]{60,}\b/, confidence: "high", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "MAPBOX_SECRET", name: "Mapbox Secret Token", pattern: /\bsk\.[a-zA-Z0-9]{60,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Crypto / Blockchain ----------
const crypto: SecretPattern[] = [
  { id: "ETH_PRIVATE_KEY", name: "Ethereum Private Key", pattern: /(?:eth[_-]?private[_-]?key|private[_-]?key)\s*[:=]\s*["'`]0x[0-9a-fA-F]{64}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "INFURA_KEY", name: "Infura API Key", pattern: /(?:infura[_-]?(?:api[_-]?)?key)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "ALCHEMY_KEY", name: "Alchemy API Key", pattern: /(?:alchemy[_-]?(?:api[_-]?)?key)\s*[:=]\s*["'`][A-Za-z0-9_-]{32}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- E-commerce ----------
const ecommerce: SecretPattern[] = [
  { id: "SHOPIFY_ACCESS", name: "Shopify Access Token", pattern: /\bshpat_[0-9a-fA-F]{32}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SHOPIFY_SHARED", name: "Shopify Shared Secret", pattern: /\bshpss_[0-9a-fA-F]{32}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SHOPIFY_CUSTOM_APP", name: "Shopify Custom App Token", pattern: /\bshpca_[0-9a-fA-F]{32}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "SHOPIFY_PRIVATE_APP", name: "Shopify Private App Password", pattern: /\bshppa_[0-9a-fA-F]{32}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Social Media ----------
const social: SecretPattern[] = [
  { id: "TWITTER_BEARER", name: "Twitter Bearer Token", pattern: /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "TWITTER_API_KEY", name: "Twitter API Key", pattern: /(?:twitter[_-]?(?:api[_-]?)?(?:key|secret))\s*[:=]\s*["'`][A-Za-z0-9]{25,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "FACEBOOK_TOKEN", name: "Facebook Access Token", pattern: /\bEAA[A-Za-z0-9]{100,}\b/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "FACEBOOK_SECRET", name: "Facebook App Secret", pattern: /(?:facebook[_-]?(?:app[_-]?)?secret)\s*[:=]\s*["'`][0-9a-f]{32}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "INSTAGRAM_TOKEN", name: "Instagram Access Token", pattern: /(?:instagram[_-]?(?:access[_-]?)?token)\s*[:=]\s*["'`]IGQ[A-Za-z0-9_-]+["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "LINKEDIN_SECRET", name: "LinkedIn Client Secret", pattern: /(?:linkedin[_-]?(?:client[_-]?)?secret)\s*[:=]\s*["'`][A-Za-z0-9]{16}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
];

// ---------- Generic Credentials ----------
const generic: SecretPattern[] = [
  { id: "PRIVATE_KEY_BLOCK", name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "BASIC_AUTH_HEADER", name: "Basic Auth Header", pattern: /(?:Authorization|authorization)\s*[:=]\s*["'`]Basic\s+[A-Za-z0-9+/=]{10,}["'`]/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "BEARER_TOKEN_HEADER", name: "Bearer Token Header", pattern: /(?:Authorization|authorization)\s*[:=]\s*["'`]Bearer\s+[A-Za-z0-9._-]{20,}["'`]/, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "CONNECTION_STRING", name: "Generic Connection String", pattern: /(?:connection[_-]?string|database[_-]?url|db[_-]?url)\s*[:=]\s*["'`]\w+:\/\/[^"'`\s]{10,}["'`]/i, confidence: "high", severity: "critical", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "GENERIC_SECRET", name: "Generic Secret Assignment", pattern: /(?:_secret|_token|_password|_key)\s*[:=]\s*["'`][A-Za-z0-9+/=_-]{20,}["'`]/, confidence: "medium", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
  { id: "WEBHOOK_URL", name: "Generic Webhook URL with Secret", pattern: /(?:webhook[_-]?(?:url|secret))\s*[:=]\s*["'`]https:\/\/[^"'`\s]{20,}["'`]/i, confidence: "medium", severity: "warning", cwe: "CWE-798", owasp: "A02:2021" },
];

export const allSecretPatterns: SecretPattern[] = [
  ...cloud,
  ...payment,
  ...communication,
  ...chat,
  ...vcs,
  ...ai,
  ...database,
  ...auth,
  ...monitoring,
  ...storage,
  ...cms,
  ...maps,
  ...crypto,
  ...ecommerce,
  ...social,
  ...generic,
];

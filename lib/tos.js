/**
 * LuaLune Terms of Service.
 * Bumping `version` forces every account to re-accept on their next sign-in.
 */

export const TOS_VERSION = "2026-09-24";

export const TOS = {
  version: TOS_VERSION,
  updated: "24 September 2026",
  contact: "support@luamore.app",
  sections: [
    {
      title: "1. The service",
      body: "LuaLune turns Lua and Luau source code into protected builds and gives you a loader URL for each one. You keep ownership of the scripts you upload. We store the protected build, the keys you create and the logs needed to run the service.",
    },
    {
      title: "2. Your account",
      body: "One person per account. Keep your password to yourself; anything done with your credentials counts as you. Accounts that stay unused for a long time may be reclaimed. You can delete a script, a key or your whole account at any time from the dashboard.",
    },
    {
      title: "3. Acceptable use",
      body: "Do not use LuaLune to distribute malware, steal credentials, bypass another developer's protections, cheat in a way that harms other players, or hide anything illegal. Do not resell access to the obfuscator or scrape the service. If we see abuse we can suspend or terminate the account without a refund.",
    },
    {
      title: "4. Protection is not a guarantee",
      body: "Obfuscation raises the cost of reading your source. It is not encryption and it cannot make a script impossible to analyse, because an executor still has to run it. Never put secrets, tokens or private keys inside a script you protect with LuaLune.",
    },
    {
      title: "5. Plans and payments",
      body: "Paid plans are one-time purchases tied to your account. Limits reset on the first of each month for build counts. Upgrades take effect immediately; downgrades take effect at the next reset. Payments are not refundable once a build has been made, except where the law says otherwise.",
    },
    {
      title: "6. Availability",
      body: "The service is provided as-is. We aim to keep loader URLs stable, but we may change or retire endpoints with notice where we can. We are not liable for lost revenue, lost scripts or downtime beyond replacing the service.",
    },
    {
      title: "7. Changes",
      body: "We may update these terms. When the version changes you will be asked to accept the new terms before you can create another build.",
    },
  ],
};

export function tosSummary() {
  return { version: TOS.version, updated: TOS.updated, contact: TOS.contact, sections: TOS.sections };
}

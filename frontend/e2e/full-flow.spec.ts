import { test, expect } from "@playwright/test";
import path from "path";

const SAMPLE_CONFIG = path.resolve(__dirname, "../../configs/synthetic/cisco-rtr-01.cfg");

test.describe.configure({ mode: "serial" });

test("full audit lifecycle: register -> upload -> scan -> compliance/risk/attack-graph -> blockchain verify -> report", async ({ page }) => {
  const uniqueSuffix = Date.now();
  const email = `e2e-${uniqueSuffix}@example.com`;

  await test.step("register a new account", async () => {
    await page.goto("/login");
    await page.click("text=Need an account? Register");
    await page.fill('input[name="fullName"]', "E2E Test User");
    await page.fill('input[name="email"]', email);
    await page.fill('input[name="password"]', "TestPass123!");
    await page.click('button[type="submit"]');
    await page.waitForURL("**/dashboard", { timeout: 15000 });
  });

  await test.step("create a project", async () => {
    await page.goto("/projects");
    await page.fill('input[name="projectName"]', `E2E Project ${uniqueSuffix}`);
    await page.click('button:has-text("Create")');
    await expect(page.locator(`text=E2E Project ${uniqueSuffix}`)).toBeVisible({ timeout: 10000 });
  });

  await test.step("upload a real Cisco configuration", async () => {
    await page.goto("/upload");
    // Wait for the project dropdown to populate before uploading -- matches
    // realistic user behavior (nobody selects a file before the page settles).
    await expect(page.locator("select")).not.toHaveValue("", { timeout: 10000 });
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(SAMPLE_CONFIG);
    await expect(page.locator("text=Analyzed")).toBeVisible({ timeout: 20000 });
    await expect(page.getByText("Cisco", { exact: true })).toBeVisible();
  });

  await test.step("start a scan from Configurations", async () => {
    await page.goto("/configurations");
    await page.click('button:has-text("Start Scan")');
    await page.waitForTimeout(1500);
  });

  await test.step("scan completes and shows compliance results", async () => {
    await page.goto("/scans");
    await page.click('a[href^="/scans/SCAN-"]');
    await page.waitForURL("**/scans/SCAN-*", { timeout: 10000 });
    await expect(page.locator("text=COMPLETED")).toBeVisible({ timeout: 20000 });
    await expect(page.locator("text=Compliance Score")).toBeVisible();
    await expect(page.locator("text=Telnet Disabled")).toBeVisible();
  });

  await test.step("attack graph tab renders a real graph", async () => {
    await page.click('button:has-text("Attack Graph")');
    await expect(page.locator(".react-flow")).toBeVisible({ timeout: 10000 });
  });

  await test.step("optimizer tab shows all three strategies", async () => {
    await page.click('button:has-text("Optimizer")');
    await expect(page.getByRole("heading", { name: "Severity Only" })).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole("heading", { name: "Greedy Risk" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "aco" })).toBeVisible();
  });

  await test.step("blockchain verification succeeds against the real Fabric ledger", async () => {
    await page.click('button:has-text("Verify Blockchain")');
    await expect(page.locator("text=BLOCKCHAIN VERIFIED")).toBeVisible({ timeout: 15000 });
  });

  await test.step("PDF report generates and download link appears", async () => {
    await page.click('button:has-text("Generate PDF Report")');
    await expect(page.locator('a:has-text("Download PDF")')).toBeVisible({ timeout: 15000 });
  });
});

import { expect, test, type Page } from '@playwright/test';
import { buildCaseFile } from '../src/casefile';
import { MODULES } from '../src/modules';
import { buildWorld } from '../src/world';

// Every request the page makes must stay on the site's own origin.
function trackForeignRequests(page: Page): string[] {
  const foreign: string[] = [];
  page.on('request', (req) => {
    const url = new URL(req.url());
    if (!['http:', 'https:'].includes(url.protocol)) return;
    if (url.origin !== 'http://localhost:4173') foreign.push(req.url());
  });
  return foreign;
}

test('home lists every module and makes no third-party requests', async ({ page }) => {
  const foreign = trackForeignRequests(page);
  await page.goto('./');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Practice the SOC');
  await expect(page.locator('.module-card')).toHaveCount(MODULES.length);
  await page.waitForLoadState('networkidle');
  expect(foreign).toEqual([]);
});

test('learn module: correct answer is accepted and unlocks the debrief', async ({ page }) => {
  const foreign = trackForeignRequests(page);
  const seed = 'e2eseed1';
  const inst = MODULES.find((m) => m.id === 'm01')!.build(buildWorld(seed));
  await page.goto(`./#/learn/m01?seed=${seed}`);
  await expect(page.getByRole('heading', { name: 'PowerShell -EncodedCommand' })).toBeVisible();
  await expect(page.locator('.locked')).toBeVisible();

  const q1 = page.locator('.question').first();
  await q1.locator('input[type=text]').fill('https://wrong.test/x');
  await q1.getByRole('button', { name: 'Check' }).click();
  await expect(q1.locator('.feedback')).toContainText('Not quite');

  await q1.locator('input[type=text]').fill(String(inst.expected.url).replace('https', 'hxxps').replace(/\./g, '[.]'));
  await q1.getByRole('button', { name: 'Check' }).click();
  await expect(q1.locator('.feedback')).toContainText('Correct');
  await expect(page.locator('.debrief')).toContainText('What interviewers listen for');
  expect(foreign).toEqual([]);
});

test('evidence bundle downloads as a zip', async ({ page }) => {
  await page.goto('./#/learn/m05?seed=e2eseed2');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /Download evidence bundle/ }).click()]);
  expect(dl.suggestedFilename()).toMatch(/\.zip$/);
});

test('interview mode runs through all three phases', async ({ page }) => {
  const seed = 'e2eseed3';
  const inst = buildCaseFile(buildWorld(seed));
  await page.goto(`./#/interview?seed=${seed}`);
  await expect(page.locator('blockquote')).toContainText('walk me through your thought process');
  await page.getByRole('button', { name: /done talking/ }).click();
  const q = page.locator('.question').first();
  await q.locator('input[type=text]').fill(String(inst.expected.user));
  await q.getByRole('button', { name: 'Check' }).click();
  await expect(q.locator('.feedback')).toContainText('Correct');
  await page.getByRole('button', { name: /Finish/ }).click();
  await expect(page.getByRole('heading', { name: /Rubric/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copy grading prompt' })).toBeVisible();
});

test('drills produce an item and grade it', async ({ page }) => {
  await page.goto('./#/drills');
  await expect(page.locator('.drill-card .drill-prompt')).toBeVisible();
  const choice = page.locator('.drill-card .choice input').first();
  if (await choice.count()) await choice.check();
  else await page.locator('.drill-card input[type=text]').fill('x');
  await page.locator('.drill-card').getByRole('button', { name: 'Check' }).click();
  await expect(page.locator('.drill-card .feedback')).toContainText(/Correct|Answer:/);
});

test('works offline after the first visit', async ({ page, context }) => {
  await page.goto('./');
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
  await page.reload();
  await page.waitForLoadState('networkidle');
  await context.setOffline(true);
  await page.reload();
  await expect(page.locator('.module-card').first()).toBeVisible();
  await context.setOffline(false);
});

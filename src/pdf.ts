// PDF output is optional: puppeteer (with its bundled Chromium) is a heavy,
// optional peer dependency, so it's imported lazily through a non-literal
// specifier and only when a PDF is actually requested.
async function launchBrowser() {
  const optionalPackage = "puppeteer";
  let puppeteer: { launch: (opts: object) => Promise<any> };
  try {
    ({ default: puppeteer } = await import(optionalPackage));
  } catch {
    throw new Error("PDF output needs puppeteer. Install it with: npm install puppeteer");
  }
  return puppeteer.launch({ headless: true });
}

// Renders the (already self-contained, no external resources) report HTML
// to a PDF buffer via headless Chromium print-to-pdf.
export async function renderReportPdf(html: string): Promise<Buffer> {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    // JavaScript stays off: the report never needs it, and its contents come
    // from the scanned repo.
    await page.setJavaScriptEnabled(false);
    await page.setContent(html, { waitUntil: "load" });
    const pdf = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: { top: "16mm", bottom: "16mm", left: "14mm", right: "14mm" },
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}

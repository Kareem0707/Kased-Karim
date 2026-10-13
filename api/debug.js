export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try {
    const binUrl = "https://extendsclass.com/api/json-storage/bin/faabcdf";
    const r = await fetch(binUrl + "?t=" + Date.now(), {
      headers: { "Accept": "application/json" }
    });
    const status = r.status;
    const text = await r.text();
    
    // Also test restful-api.dev
    const restUrl = "https://api.restful-api.dev/objects/ff808181a09d98f701a1374695f857d7";
    const r2 = await fetch(restUrl);
    const restStatus = r2.status;
    const restText = await r2.text();

    return res.status(200).json({
      extendsclass: { status, body: text.slice(0, 200) },
      restful: { status: restStatus, body: restText.slice(0, 200) }
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

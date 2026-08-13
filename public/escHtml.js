// Kullanıcı girdisini (mold_id, description vb.) innerHTML içine güvenle basmak için
function escHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c];
  });
}
if (typeof module !== "undefined" && module.exports) module.exports = escHtml;

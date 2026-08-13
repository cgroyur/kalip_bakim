"use strict";

// Orijinal POST /api/state merge mantığındaki tek-WO çakışma kararının birebir
// çıkarılmış hali — hem pgStore hem fileStore aynı kararı versin diye paylaşılıyor.
// Kural (değişmedi): SADECE updated_at karşılaştırılır (created_at'e düşülmez).
function shouldOverwriteWo(existing, incoming) {
  if (!existing) return true; // yeni WO
  const sHas = !!existing.updated_at;
  const cHas = !!incoming.updated_at;
  if (sHas && cHas) {
    return new Date(incoming.updated_at).getTime() >= new Date(existing.updated_at).getTime();
  }
  if (cHas && !sHas) return true; // sadece client değişmiş — client kazanır
  if (sHas && !cHas) return false; // sadece sunucu değişmiş — sunucu kazanır
  return true; // ikisinde de yok — client kazanır (son gönderen)
}

module.exports = { shouldOverwriteWo };

function renderResults(results, searchTerm) {
  const box = document.getElementById("results");
  box.innerHTML = `<h2>Results for ${searchTerm}</h2>` +
    results.map(r => `<li>${r.name}</li>`).join("");
}

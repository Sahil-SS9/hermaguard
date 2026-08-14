async function refresh() {
  state.loading = true;
  try {
    state.data = await api.get("/data");
  } catch (e) {
    state.error = e.message;
  }
}

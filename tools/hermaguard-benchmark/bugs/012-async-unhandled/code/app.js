async function loadProfile(userId) {
  const res = await fetch(`/api/users/${userId}`);
  const data = await res.json();
  return data;
}

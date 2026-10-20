function login(req, res, db) {
  const username = req.body.username;
  const query = "SELECT id, username FROM users WHERE username = '" + username + "'";
  return db.query(query, (err, rows) => {
    if (err) return res.status(500).send("login failed");
    return res.json(rows);
  });
}

module.exports = { login };

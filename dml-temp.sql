INSERT INTO users (username, password, role)
VALUES ('admin', 'admin123', 'admin');
INSERT INTO users (username, password, role)
VALUES ('john', 'john123', 'user');
INSERT INTO users (username, password, role)
VALUES ('jane', 'jane123', 'user');
-- UPDATE versi HASHED
UPDATE users
SET password = '$2b$10$/8HO/ourBxzGRbCy8YIgl.cPcW.qC/8DWlyNFZkB5pzas8kA09u8y'
WHERE id = 1;
UPDATE users
SET password = '$2b$10$gbrhjSTmjZHDOwQys1qe0umHtkIEGduPXbmYFxGjeVTTgE9H3HOIO'
WHERE id = 2;
UPDATE users
SET password = '$2b$10$HN9WT.5L.h9Sf8XITACYCOcKtDTyYRucia.PLR3GAZep/q/gDj.wu'
WHERE id = 3;
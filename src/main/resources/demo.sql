INSERT INTO users (
    username,
    credentials_expired,
    enabled,
    expired,
    locked,
    "password",
    "token") VALUES
('Admin', false, true, false, false, '$2a$12$8fVmEpPRWT75YkcjL5fmGeQ.se8NiQSEjSoDB6FQTLB9hghxsisWy', null), -- Пароль admin
('User', false, true, false, false, '$2a$12$.6880LFl5C/ItfPq/.RcdecFI9dRUUeKNTqOsIKVd5V1Fv1EK/s52', null); -- Пароль 1234

INSERT INTO authorities (
    username,
    authority) VALUES
('Admin', 'ROLE_ADMIN'),
('User', 'ROLE_USER');

select
    u.credentials_expired,
    u.enabled,
    u.expired,
    u.locked,
    u."password",
    u."token",
    u.username
from
    users u;

select
    a.authority,
    a.username
from
    authorities a;
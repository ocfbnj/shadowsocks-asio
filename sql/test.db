create table if not exists record (
    request_host varchar(255) not null,
    target_host varchar(255) not null,
    bytes bigint default 0,
    times int default 1,

    primary key(request_host, target_host)
);

insert or ignore
into
    record (request_host, target_host, bytes)
values
    ("127.0.0.2", "google.com", 32768);

update
    record
set
    bytes = bytes + 32768,
    times = times + 1
where
    request_host="127.0.0.2" and target_host="google.com";

select
    request_host, sum(bytes) / 1024 / 1024 as MB
from
    record
group by
    request_host;

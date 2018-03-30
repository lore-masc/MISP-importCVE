use misp;
delete from events;
delete from tags;
delete from attributes;
delete from event_tags;
delete from attribute_tags;
alter table events auto_increment = 1;
alter table tags auto_increment = 1;
alter table attributes auto_increment = 1;
alter table event_tags auto_increment = 1;
alter table attribute_tags auto_increment = 1;


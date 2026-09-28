# Tec-Tac Framework 1.15.84

## Scheduler history pagination and authorization

- Added bounded server-side pagination for Scheduler run history with a maximum page size of 100.
- Added server-side run-history search plus status, owner and schedule filters.
- Scheduler managers use database count/offset paging; scoped operators are authorization-filtered before visible rows are counted.
- Scoped history scanning uses queryset iteration so retained history is not materialized as one large Python list.
- Preserved the legacy bounded unpaged response for older Core/UI consumers.
- Invalid `schedule_id`, page values and run statuses now return a controlled 400 response.
- Added regression coverage for the paged history contract and legacy compatibility path.

# Example reportset

Reference implementation only. This is not a production Tec-Tac reportset.

The `example` reportset demonstrates the reporting/data-mapping side owned by `extensions/example/`. It accepts the extension's raw sample record and maps it into a report-facing representation.

`tec_tac_example_reportset.sample.map_sample_data()` deliberately performs only a tiny transformation. Real reportsets may define mappings, enrichment, relationships, aggregations and report-facing models for their owning extension.

# Detection lab

Tools for measuring how well Whereabouts detects problems, **using lab data only, never real users' data**. See the [design spec, section 6.6](../docs/design-spec.md#66-evaluation-lab-never-on-user-data).

Planned contents:

- scripted app sessions in Windows virtual machines (normal behaviour)
- injected scenarios: hidden uploads, beaconing, random-looking domains, known-bad hosts, renamed binaries
- an evaluation harness reporting false alarms per user per week, detection rate and time to detect, for each detection layer

Nothing in this folder is shipped with the app. Raw captures and outputs are git-ignored.

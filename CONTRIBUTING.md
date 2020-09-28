# Contributing

Thank you for thinking about contributing. This is a small project that really
only existed to support an interest in reverse engineering Apple II application
binaries. However, the result seems more flexible that the standard Ghidra
string analyzer.

Contributions that improve the quality of the project such that it could be
given back to the Ghidra project are welcome. Therefore you are encouraged to
read the Ghirda Contributing document and DevGuide.

Specific contributions that would be appreciated are:
 - Unit tests of the iterator classes, CharsetStringAnalyzer, and search
   character set option editor classes.
 - Test data for different character sets with and without alignment of
   different sizes.
 - A fix for the awful layout of the analyzer options layout with the
   character set selection table.

While new features or functions will be considered, especially if suggested in
the form of a fully tested pull request, the focus is on improving the quality
of existing capability.

## Guidelines

Content is encouraged, but a well thought out defect report is welcome. That
requires the following:
 - A clear description of how current behavior deviates from desired or expected
   (note that is often a matter of opinion and someone else may disagree with
   you).
 - Instructions to reproduce. It's hard to give guidance on how detailed the
   instructions have to be. Be prepared to negotiate.
 - Test data or assets as required. Given that Ghidra is a reverse engineering
   tool, it's probably necessary to mention that you can't supply someone's
   proprietary code. If you have to, recreate the problem with unencumbered
   test data.

Before contributing code, please review the LICENSE and NOTICE files. To keep
things simple, contributions must be made with an Apache License, Version 2.0.
Contributed code must be correctly attributed. This may be by combining the
code contributed with an update to the NOTICE file.

No reformatting of code to suit your preferred line breaks, indentation, imports
organization, etc. This is mostly because changes like this mess with source
control blame annotations.

While your own contributions are not going to be exhaustively checked against a
312 point code style guide,do roughly follow the style of the files you are
modifying so that your own contribution looks like it belongs there.

That's about it in terms of formal guidelines. This project is currently very
much a one man show in the quiet hours after dinner. There is no social media.
There is no project website. Code review consists of a quick once over without
too many "Ewww!" moments.

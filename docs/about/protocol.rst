Protocol reference
==================

Control port implementation was written based on multiple documentation sources.

Of course the bible is the `Control Spec`_, published by the `Tor project`_.
The text version is a little bit easier to deal with compared to the `HTML version`_,
which was also used for this project.

Due to many questions left after reading these documents, the `source code of Tor`_ was
also taken into account. It allowed the removal of deprecated commands, replies or events
when they were removed a long time ago, or are sometimes described in the documentation but
were never implemented.

This hopefully ensures a better match between our implementation and the real protocol in Tor.

.. _Control Spec: https://gitlab.torproject.org/tpo/core/torspec/-/tree/main/spec/control-spec
.. _HTML version: https://spec.torproject.org/control-spec/index.html
.. _source code of Tor: https://gitlab.torproject.org/tpo/core/tor
.. _Tor project: https://www.torproject.org

For any error, please consider :ref:`contributing` through an issue or a pull request.

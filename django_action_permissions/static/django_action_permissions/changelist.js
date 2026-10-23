/* The action permissions' list: a tool link marked data-selection="<param>" (Overview, Verify) carries the rows
 * checked in the list as `<param>=<pk>` (the first data-selection-max of them, when set), so the tool opens on them.
 * Without JS, or with no row checked, the link is followed as it is. */
(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    const link = event.target.closest && event.target.closest("a[data-selection]");
    if (!link) return;
    let selected = Array.prototype.map.call(
      document.querySelectorAll("#changelist-form input.action-select:checked"),
      function (checkbox) {
        return checkbox.value;
      }
    );
    const max = parseInt(link.dataset.selectionMax, 10);
    if (max > 0) selected = selected.slice(0, max);
    const url = new URL(link.getAttribute("href"), window.location.href);
    url.searchParams.delete(link.dataset.selection);
    selected.forEach(function (pk) {
      url.searchParams.append(link.dataset.selection, pk);
    });
    link.href = url.toString();
  });
})();

$(document).ready(function() {
    $('#analyzeBtn').click(function() {
        var file = $('#fileInput')[0].files[0];
        var formData = new FormData();
        formData.append('file', file);

        $.ajax({
            url: '/analyze',  // backend endpoint
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                var tbody = $('#resultsTable tbody');
                tbody.empty();
                response.forEach(row => {
                    tbody.append(
                        `<tr>
                            <td>${row.id}</td>
                            <td>${row.attack_cat}</td>
                            <td>${row.label}</td>
                            <td>${row.cluster}</td>
                        </tr>`
                    );
                });
            },
            error: function(err) {
                alert('Error analyzing file');
            }
        });
    });
});

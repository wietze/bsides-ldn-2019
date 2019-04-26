function flash(id, msg) {
    $(function () {
        document.getElementById(id).innerHTML = msg;
        $('#' + id).delay(1000).fadeIn('normal', function () {
            $(this).delay(1000).fadeOut();
        });
    });
}

rel_url = '';
rel_url_adversary = rel_url + '/adversary';
rel_url_adversary_gui = rel_url_adversary + '/gui';

$(".slides").sortable({
    placeholder: 'slide-placeholder',
    axis: "y",
    revert: 150,
    start: function (e, ui) {

        placeholderHeight = ui.item.outerHeight();
        ui.placeholder.height(placeholderHeight + 15);
        $('<div class="slide-placeholder-animator" data-height="' + placeholderHeight + '"></div>').insertAfter(ui.placeholder);

    },
    change: function (event, ui) {

        ui.placeholder.stop().height(0).animate({
            height: ui.item.outerHeight() + 15
        }, 300);

        placeholderAnimatorHeight = parseInt($(".slide-placeholder-animator").attr("data-height"));

        $(".slide-placeholder-animator").stop().height(placeholderAnimatorHeight + 15).animate({
            height: 0
        }, 300, function () {
            $(this).remove();
            placeholderHeight = ui.item.outerHeight();
            $('<div class="slide-placeholder-animator" data-height="' + placeholderHeight + '"></div>').insertAfter(ui.placeholder);
        });

    },
    stop: function (e, ui) {
        $(".slide-placeholder-animator").remove();
    },
});


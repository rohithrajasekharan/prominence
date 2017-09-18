$(window).load(function () {
    var i = 0;
    var images = [
        '/images/one.jpg','/images/two.jpg','/images/three.jpg','/images/four.jpg','/images/five.'];
    $('.hero').css('background-image', 'url(' + images[i] + ')');
    setInterval(function () {
        if (++i === images.length) {
            i = 0;
        }
        $('#nextimg').css('background-image', 'url(' + images[i] + ')');
        // transition animation: 2s
        $('.hero').fadeIn(500, function () {
            $('.hero').css('background-image', 'url(' + images[i] + ')').show();
        });
        // slide change: 3s
    }, 2000);
});

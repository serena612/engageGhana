var months=['January','February','March','April','May','June','July','August','September','October','November','December'];
$(function () {
    var timers = $(".timer");
    for (let i = 0; i < timers.length; i++) {
        const element = timers[i];
        countdownTimeStart(element);
    }

})
// if(window.location.href=='https://cms.engage.devapp.co/' || window.location.href=='https://cms.engage.devapp.co')
// {
//     window.location.href='https://cms.engage.devapp.co/admin/'
// }
$(document).on('show.bs.modal', '#login-modal', function (e) {
    var message = '';

    var relatedTarget = $(e.relatedTarget);
    if (relatedTarget.hasClass('html5-game')) {
        //message = 'Please login or register to Engage to be able to play leisure games, earn coins, and win multiple prizes'
        message = leisureGames_transl
    } else if (relatedTarget.hasClass('featured-game')) {
        //message = 'Please login or register to Engage to be able to play featured games and win multiple prizes'
        message =featuredGames_transl 
    } else if (relatedTarget.hasClass('join-now')) {
       // message = 'Please login or register to Engage to be able to join tournaments and compete with others to earn many cash and other prizes'
       message = joinNow_transl
    }
    else if (relatedTarget.hasClass('get-btn')) {
        //message = 'Please login or register to Engage to buy coins, increase your balance, and win multiple cash and other prizes'
        message = getBtn_transl
    }
    else if (relatedTarget.hasClass('pack_a')) {
       // message = 'Please login or register to Engage to redeem gifts and win multiple cash and other prizes'
       message = redeemGifts_transl
    }
    $(e.currentTarget).find('p.message').html(message);
    
});

$(document).on("click", "#open-left, #sidebar-close", function (e) {
    e.preventDefault();
    $(".sidebar").toggleClass("active");
})

$(document).on("click", ".buy-coins-btn", function (e) {
    const amount = $(this).attr("data-amount");
    var buyCoinsModalMessage = `You are about to get ${amount} additional coins added to your balance. Press Confirm to Proceed?`;
    $("#buy-coins-message").html(buyCoinsModalMessage);
})

$(document).on("click", ".sidebar .s-menu a", function (e) {
    $(".sidebar").toggleClass("active");
})

$(document).click(function (e) {

    if (
        $(e.target).hasClass("notification-btn") ||
        $(e.target).parents(".notification-btn").length > 0 ||
        $(e.target).parents(".notification-drop").length > 0
    ) {

    } else {
        if ($(".notification-dropdown").hasClass("show-notification")) {
            $(".notification-dropdown").removeClass("show-notification");
        }
    }

    if (
        $(e.target).hasClass("search-btn") ||
        $(e.target).parents(".search-btn").length > 0 ||
        $(e.target).parents(".search-box").length > 0
    ) {

    } else {
        if ($("body").hasClass("search-opened")) {
            $(".search-btn").click();
        }
    }
});

$(document).on("click", ".notification-btn", function () {
    $(".notification-dropdown").toggleClass("show-notification");
});

$(document).on("click", ".go-to-login-btn", function (e) {
    e.preventDefault();
    $("#register-modal").modal("hide");
    $("#login-modal").modal("show");
});

// $(document).on("click", ".go-to-register-btn", function (e) {
//     e.preventDefault();
//     $("#login-modal").modal("hide");
//     $("#register-modal").modal("show");
// });

$(document).on("click", "#login-otp-btn", function () {
    var code = $("#login-otp-input").val();
    
});

/* $(window).on("hashchange", function (e) {
     hashchanged();
}); */
$(document).ready(function(){
    if($('.profile-parent-page').length!=0){
        if($('.tournament-page-content').length!=0){
        $('body').addClass('adjust_style1');
        }
        
        else{
            $('body').addClass('adjust_style');  
        }
    }
    else if($('.prizes-sec').length!=0){
        $('body').addClass('adjust_style3');
     }
    
})
//$(window).on('load', function() {
//    hashchanged();
//});



  

// setTimeout(() => {
//     hashchanged();
// }, 200);

$(document).on("click", ".slid-parent .slid-item .close-btn", function () {
    $(this).closest(".slid-item").removeClass("open-details");
});

$(document).on("shown.bs.modal", "#reset-modal", function () {
    $("#login-modal").modal("hide");
});

$(document).on("click", ".avatar-select > img", function () {
    $(this).closest(".avatar-select").toggleClass("open");
});

$(document).on("click", ".avatar-select .avatar-drop .avatar-item", function () {
    var src = $(this).attr("src");
    var id = $(this).data("id");

    var img = $(this).closest(".avatar-select").find("> img");
    var input = $(this).closest(".avatar-select").find("input");

    img.attr("src", src);
    input.val(id);

    $(this).closest(".avatar-select").removeClass("open");
});

$('.is-with-side-friends').click(function(){
    $('.expand-box.expanded').find('.expand-link').click()
})

$(document).on("click", ".expand-link", function (e) {
    e.preventDefault();
    var parent = $(this).closest(".expand-parent");
    var box = $(this).closest(".expand-box");
    parent.toggleClass("expanded");

    var size = null;
    if (parent.hasClass("expanded")) {
        box.addClass("expanded");
        $(this).html("Go Back");

        $([document.documentElement, document.body]).animate({
                scrollTop: box.offset().top - 20,
            },
            400
        );
    } else {
        box.removeClass("expanded");
        $(this).html("View All");

        if (box.data("min-size")) {
            size = box.data("min-size");
        }
    }

    var target = $(this).data("target");

    switch (target) {
        case "last_played_games":
            getLastPlayedGames(user_uid, box.find(".imgs-box"), size);
            break;

        case "joined_tournaments":
            getJoinedTournaments(user_uid, box.find(".newsbv"), size);
            break;

        case "stickers":
            getStickers(user_uid, box.find(".imgs-box"), size);
            break;

        case "trophies":
            getTrophies(user_uid, box.find(".imgs-box"), size);
            break;

        default:
            break;
    }

    $(window).trigger("resize")
});

$(function () {
    
    $(".slid-parent").slick({
        dots: true,
        infinite: false,
        speed: 300,
        arrows: false,
        slidesToShow: 3,
        slidesToScroll: 1,
        responsive: [{
            // breakpoint: 2000,
            // settings: {
            //     slidesToShow: 3,
            // },
            // },
            // {
                breakpoint: 600,
                settings: {
                    dots: true,
                    slidesToShow: 1,
                },
            },
            {
                breakpoint: 480,
                dots: true,
                settings: {
                    slidesToShow: 1,
                },
            },
        ],
    });

  
    $(".slid-parent .text-content")
        .click(function () {
            $(this).parents(".slid-item").addClass("open-details");
        })

    $(".levels-slider").slick({
        slidesToShow: 5,
        infinite: false,
        responsive: [{
            breakpoint: 1024,
            settings: {
                slidesToShow: 3,
            },
        },
            {
                breakpoint: 600,
                settings: {
                    slidesToShow: 3,
                },
            },
            {
                breakpoint: 480,
                settings: {
                    slidesToShow: 2,
                },
            },
        ],
    });

    setTimeout(() => {
        $(".loading-box").slideUp(600, function () {
            $("body").removeClass("is-loading");
        });
    }, 500);
    checkSeenCoins();
});

$(function () {
    var $grid = $(".grid-gal").isotope({
        itemSelector: ".grid-item",
        percentPosition: true,
        masonry: {
            columnWidth: ".grid-sizer",
        },
    });

    $grid.imagesLoaded().progress(function () {
        $grid.isotope("layout");
    });

    $(".isotopeMenu a").click(function (e) {
        e.preventDefault();
        var t = $(this).attr("href");
        $grid.isotope({
            filter: t,
        });
        $(this).closest("ul").find("li").removeClass("active");
        $(this).closest("li").addClass("active");
    });
});

var isShowing = false;
$(document).on("click", ".tabs-container a,.firstTab a,.secondTab a", function () {
    if (isShowing) return;
    var target = $($(this).attr("data-id"));
    var txtTarget=$(this).attr("data-id");
    if (!target.length) return;
    if (target.is(":visible")) return;
    isShowing = true;
    $(this).closest(".tabs-container").find("a").removeClass("active");
    $(".block_tabs").hide();
    $(".tab-section").hide();
    $(this).addClass("active");
    target.show();
    if(txtTarget=='#latest')
    {
        $('.firstTab').css('display','flex');
        $('.secondTab').hide();
        //$('.firstTab').find('a').eq(0).click();
        $('.tournament_game_content').hide();
        $('#tournament_dv').show();
    }
    else{
        $('.firstTab').hide();
        $('.secondTab').css('display','flex');
        $('.secondTab').find('a').eq(0).click();
        $('.tournament_game_content').show();
        $('#tournament_dv').hide();
    }
    var sub_tabs = $(target.find(".nav-tabs"));
    if (sub_tabs.length > 0) {
        $(sub_tabs.find("li")[0]).find("a").click();
    }
    // if ($(this).hasClass("is-with-side-friends")) {
    //     $(".profile-parent-page").addClass("with-side-friends");
    // } else {
    //     $(".profile-parent-page").removeClass("with-side-friends");
    // }

    $(window).trigger("resize");
    isShowing = false;

});

function hashchanged() {
    
    setTimeout(function(){
    var hash = window.location.hash;

        switch (hash) {
            case "#home-tournaments":
            
                var c=$("#sec-3").offset().top;
            
        
                $([document.documentElement, document.body]).animate({
                        scrollTop: $("#sec-3").offset().top-50,
                    },
                    c/1.35
                );
                $("#sec-3 a.tour-btn").click();
                resetStar($('#hometournaments'));
                break;

            case "#home-games":
                var i=$("#sec-3").offset().top;
                $([document.documentElement, document.body]).animate({
                        scrollTop: $("#sec-3").offset().top-50,
                    },
                    i/1.35
                );
                $("#sec-3 a.games-btn").click();
                resetStar($('#homegames'));
                break;

            case "#winners":
                var w=$(".sec-3-1").offset().top;
                    $([document.documentElement, document.body]).animate({
                            scrollTop: $(".sec-3-1").offset().top-50,
                        },
                        w/1.35
                    );
                    
                
                    resetStar($('#li_winners'));
                    
                    break;
        
            case "#redeem-coins":
                var t=$("#prizes_page").offset().top;
                $("#prizes_page #coins").click();
                // $([document.documentElement, document.body]).animate({
                //         scrollTop: $("#prizes_page").offset().top-50,
                //     },
                //     t/1.35
                // );
            // resetStar($('#a-redeem'));
                break;
            
            case"#tournament-prizes":
                    //var t=$("#prizes_page").offset().top;
                // $("#prizes_page #tournaments").click();
                    // $([document.documentElement, document.body]).animate({
                    //         scrollTop: $("#prizes_page").offset().top-50,
                    //     },
                    //     t/1.35
                    // );
                //  resetStar($('#a-prize'));


























                    break;









            default:
                if (hash.length > 1) {
                    $("a[href='" + hash + "']").click();
                }
                break;
        }

   },500);
    $(window).trigger("resize");
    
  
}

function hiya(){
    

        window.location.href="#home-tournaments";






  
}

function hashchangeddd() {
    
    setTimeout(function(){
    var hash = window.location.hash;
   
    switch (hash) {
       
         case "#winners":
            var w=$(".sec-3-1").offset().top;
            
           
                $([document.documentElement, document.body]).animate({
                        scrollTop: $(".sec-3-1").offset().top-50,
                    },
                   1000
                );
                resetStar($('#li_winners'));
    
                break;

        default:
            if (hash.length > 1) {
                $("a[href='" + hash + "']").click();
            }
            break;
    }
    
    },500);
    $(window).trigger("resize");
}

$(function () {
    $(window).trigger("resize");
    
});

$(document).ready(function(){setTimeout(function(){
    checkSeenCoins();
},500);})

$(window).on("resize", function () {
    if($('.sec-3-1').length!=-1){
        $('.sec-3-1').find('.scroll_wrapper').css('width',$('.sec-3-1').find('.package').length*$('.sec-3-1').find('.package').outerWidth(true));
    }
    var boxes = $("[data-scroll-max]");
    for (let i = 0; i < boxes.length; i++) {
        const box = $(boxes[i]);
        setupScrollBox(box);
        box.find("img").on("load", function () {
            setupScrollBox(box);
        });
    }

    var pcontent = $(".page-tab-content:visible .profile-contain");
    if (pcontent.length > 0) {
        $(".side-friends").css("height", pcontent.outerHeight());
    }
    if($('.desktopversion').length>0){
        $('.desktopversion .block_tabs').css('width',(3*$('.desktopversion .package').outerWidth(true)));
        $('.mobileversion').find('.list').each(function(){
            if($(this).find('.newsbv-item').length!=0){
               $(this).css('width',($(this).find('.newsbv-item').length*($(this).find('.newsbv-item').width() + 15)));
               $(this).removeClass('hide')
            }
            else{
               $(this).addClass('hide'); 
            }
        });
    }
});

function setupScrollBox(box) {
    var child = box.find(box.attr("data-scroll-child"));
    var h = child.outerHeight(true);

    var max = parseInt(box.attr("data-scroll-max"));
    var max_h = h * max;

    var min = 0;
    if (box.attr("data-scroll-min")) {
        min = parseInt(box.attr("data-scroll-min"));
    }
    var min_h = h * min;

    var add = 0;
    if (box.attr("data-scroll-add")) {
        add = parseInt(box.attr("data-scroll-add"));
    }

    box.css({
        "max-height": (max_h + add) + "px",
        "min-height": (min_h + add) + "px",
    });
}

$(function () {
    $(".top-nav .search-box select").select2({
        minimumResultsForSearch: -1,
        allowClear: true
    });
});

$(document).on("input", ".top-nav .search-box input", function () {
    var text = $(this).val();
    if (text.length >= 3) {
        $(".top-nav .search-box button[type=submit]").prop("disabled", false);
    } else {
        $(".top-nav .search-box button[type=submit]").prop("disabled", true);
    }
});

var is_search_toggling = false;
$(document).on("click", ".top-nav .search-btn, .top-nav .search-box .close-btn", function (e) {
    e.preventDefault();
    if (is_search_toggling) return;
    is_search_toggling = true;
    $("body").toggleClass("search-opened");
    if ($("body").hasClass("search-opened")) {
         //meeee
         $('.user_profile_pic.top_profile_pic').addClass('opened');
         $('nav .midlle a.logonew').addClass('opened');
        $(".top-nav .search-box").fadeIn(200, function () {
            is_search_toggling = false;
        });
    } else {
            //meeee
        $('.user_profile_pic.top_profile_pic').removeClass('opened');
        $('nav .midlle a.logonew').removeClass('opened');
        $(".top-nav .search-box").fadeOut(200, function () {
            is_search_toggling = false;
            
        });
    }
    resetNavSearch();
})

$(document).on("change", "#nav-search-select", function () {
    resetNavSearch();

})

function openEditProfileModal(event) {
    if (event)
        event.preventDefault();

    setTimeout(function(){loadAvatars();},1000);
    var modal = $('#settings-modal');

    modal.find(".error").remove();
    modal.find(".avatar-select img.selected-avatar-img").attr("src", profileData.avatar_url);
    modal.find("[name=avatar]").val(profileData.avatar_id);
    modal.find("[name=name]").val(profileData.nickname);
    modal.find("[name=email]").val(profileData.email);
    modal.find("[name=data_month]").val(profileData.birthdate_month);
    modal.find("[name=data_day]").val(profileData.birthdate_day);
    modal.find("[name=data_year]").val(profileData.birthdate_year);
    modal.find("[name=country]").val(profileData.country);
    modal.find("[name=gender]").val(profileData.gender);
    modal.find("[name=residency]").val(profileData.residency);
    if($('.profile-parent-page').length==0){
        $('body').addClass('newchange');
    }
    modal.modal();

     $(".modal").on('hidden.bs.modal', function () {
            $('body').removeClass('newchange');
    //      $('body').removeClass('modal-open');
    //      $('.modal-backdrop').remove();
    //      $('#notifications-popup').find('.modal').removeClass('fade');
    //      $('#notifications-popup').find('.modal').css('display','none');
     })
}


function openLiveModal(link){
    var modal = $('#live-modal');
    modal.find('iframe').attr('src',link);
    modal.modal();
    $(".modal").on('hidden.bs.modal', function () {
        modal.find('iframe').attr('src','');
    });
}


function openLiveWindow(link) {
  window.open(link, '_blank');
}

function resetNavSearch() {
    var results_list = $(".top-nav .search-box .results-box ul");
    results_list.empty();
    var search_input = $(".top-nav .search-box input");
    search_input.val("")
}

// Set favorite
$(document).on("click", "#friends-list .star-btn", function (e) {
    e.preventDefault();
    var btn = $(this);
    var uid = $(this).closest("li").data("id");
    setFriendFavorite(uid).then(res => {
        if (res.is_favorite) {
            btn.addClass("is-fav");
        } else {
            btn.removeClass("is-fav");
        }
        return res;
    }).catch(e => {
        console.log("e", e);
    })
})

var current_remove_uid = null;
$(document).on("click", "#friends-list .remove-btn", function (e) {
    e.preventDefault();
    $("#remove-friend-modal").modal();
    var uid = $(this).closest("li").data("id");
    current_remove_uid = uid;
})

$(document).on("click", "#remove-friend-btn", function (e) {
    e.preventDefault();
    setBtnLoading($(this), true);
    removeFriend(current_remove_uid).then(res => {
        $("[data-id='" + current_remove_uid + "']").remove();
        current_remove_uid = null;
        $("#friends-count").html(parseInt($("#friends-count").html()) - 1)
        $("#remove-friend-modal").modal("hide");
        setBtnLoading($(this), false);
        return res;
    }).catch(e => {
        setBtnLoading($(this), false);
    })
})


$(document).on("click", "#remove-friend-button", function (e) {
    e.preventDefault();
    setBtnLoading($(this), true);
    removeFriend(current_remove_uid).then(res => {
        $("#remove-friend-public").remove();
        $("#remove-friend-modal").modal("hide");
        setBtnLoading($(this), false);
        return res;
    }).catch(e => {
        setBtnLoading($(this), false);
    })
})


// Send Coins

$(document).on("click", ".send-coins-btn", function (e) {
    e.preventDefault();
    var uid = $(this).closest("li").data("id");
    $("#send-coins").find("input[name=friend]").val(uid);
    $('#send-coins-form').find('.input-number').val(1);
    $("#send-coins").find(".response-msg").html("");
    $("#send-coins").modal();
})

$(document).on("click", ".input-number-box .input-number-increment", function () {
    var input = $(this).closest(".input-number-box").find("input");
    var num = parseInt(input.val()) + 1;
    input.val(num);
});

$(document).on("click", ".input-number-box .input-number-decrement", function () {
    var input = $(this).closest(".input-number-box").find("input");
    var num = parseInt(input.val()) - 1;
    if (num < 1) num = 1;
    input.val(num);
});

$(document).on("input", ".input-number-box input", function () {
    this.value = this.value.replace(/\D/g, '');
});

$(document).on("change blur", ".input-number-box input", function () {
    if ($(this).val().trim().length === 0) {
        $(this).val(1);
    }
});


/* HELPERS */

function inputToB64(event) {
    var file = event.files[0];

    var img_url = window.URL.createObjectURL(file);
    var img_thumb = $($(event).data("img-thumb"));
    if (img_thumb) {
        img_thumb.attr("src", img_url);
    }

    var input = $($(event).data("b64-input"));
    var reader = new FileReader();
    reader.readAsBinaryString(file);

    reader.onload = function () {
        input.val(btoa(reader.result));
    };
    reader.onerror = function () {
        console.log("there are some problems");
    };
}

function getNumberWithOrdinal(n) {
    var s = ["th", "st", "nd", "rd"],
        v = n % 100;
    return n + (s[(v - 20) % 10] || s[v] || s[0]);
}

function mobilecheck() {
    var userAgent = navigator.userAgent || navigator.vendor || window.opera;

    if (/android/i.test(userAgent)) {
        return "android";
    }

    // iOS detection from: http://stackoverflow.com/a/9039885/177710
    if (/Mac|iPad|iPhone|iPod/.test(userAgent) && !window.MSStream) {
        return "ios";
    }

    return "pc";
}

function big_number(value) {
    if (value >= 1000000) {
        value = (value / 1000000) + "M"
    } else if (value >= 1000) {
        value = (value / 1000) + "K";
    }
    return value;
}

function getFormData($form) {
    var url = $form.attr("action");
    var method = $form.attr("method");

    var unindexed_array = $form.serializeArray();
    var indexed_array = {};

    $.map(unindexed_array, function (n, i) {
        indexed_array[n['name']] = n['value'];
    });

    return {
        data: indexed_array,
        url: url,
        method: method
    };
}

function setBtnLoading(btn, status) {
    if (status) {
        $(btn).addClass("is-loading");
    } else {
        $(btn).removeClass("is-loading");
    }

    $(btn).prop("disabled", status);
}

$(function () {
    function getCookie(name) {
        var cookieValue = null;
        if (document.cookie && document.cookie !== "") {
            var cookies = document.cookie.split(";");
            for (var i = 0; i < cookies.length; i++) {
                var cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === name + "=") {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }

        return cookieValue;
    }

    var csrftoken = getCookie("csrftoken");

    $("body").delegate(".html5-game", "click", function (e) {
        e.preventDefault();
        
        if ($(this).hasClass("is-locked")){
            if($(this).attr('data-target')!="#login-modal"){
                
                if($("#userSub").val() == "free" ){
                    //$("#games-subscription-notifications #games-notifications-title").text("Upgrade Subscription");
                    //$("#games-subscription-notifications #games-notifications-body").text("Please upgrade your package to play this game.");
                    $('#upgrade-package-pgame-modal').modal('show');
                }else if($("#userIsBilled").val() == "False" )
                { 
                    $("#games-subscription-notifications #games-notifications-title").text("Recharge Line!");
                    $("#games-subscription-notifications #games-notifications-body").text('You don\'t have enough balance to play this game. Please recharge your line and try again.');
                    $("#games-subscription-notifications").modal({
                        show: true,
                        keyboard: true,
                        backdrop: true,
                    });
                }
                
            }
            return;
        }
        $("#remove-friend-modal").modal("hide");
        
        var target = $(this).attr("data-target");
    //    if(user_subscription=='paid2'){
    //         $("#googleadd-modal").modal("show");

    //        $('.closeAdd').click(function(){
    //         if($("#googleadd-modal video,#googleadd-modal iframe").length>0)
    //         $("#googleadd-modal video,#googleadd-modal iframe")[0].src += "?autoplay=0";});
    //         $('#googleadd-modal video,#googleadd-modal iframe').on('ended', function(){
    //             $.ajax({
    //                 url: `/games/${target}/`,
    //                 headers: {
    //                     "X-CSRFToken": csrftoken,
    //                 },
    //                 async: false,
    //                 type: "get",
    //                 data: {},
    //                 error: function (value) {
                        
    //                     var {
    //                         responseText,
    //                         status
    //                     } = value;
    //                     if (status === 404) {
    //                         $("#games-notifications #games-notifications-title").text("GAME NOT FOUND");
    //                         $("#games-notifications #games-notifications-body").text("Game Not Found");
    //                     }
                      
    //                     else if (status === 403) {
    //                         $("#games-notifications #games-notifications-title").text("Free Subscription");
    //                         $("#games-notifications #games-notifications-body").text(responseText);
                           
    //                      }
    //                     else if (status === 410) {
    //                         $("#games-notifications #games-notifications-title").text("Premium Games");
    //                         $("#games-notifications #games-notifications-body").text(responseText);
                            
                            
    //                     }
    //                     else {
    //                         $("#games-notifications #games-notifications-title").text("Error");
    //                         $("#games-notifications #games-notifications-body").text("Something Went Wrong");
    //                     }
                        
    //                     $("#games-notifications").modal({
    //                         show: true,
    //                         keyboard: true,
    //                         backdrop: true,
    //                     });
                       
    //                 },
    //                 success: function (value) {
    //                     var isIOS = /(iphone)/i.test(navigator.userAgent);
    //                     var isAnroid = navigator.userAgent.toLocaleLowerCase().indexOf("android") > -1;
                       
                         
                     
    //                     if(isIOS || isAnroid){
    //                     //window.location.href=`/games/${target}/`;
    //                     $('#game-fullscreen-modal').find('.modal-content').css('width',$(window).width());
    //                     $('#game-fullscreen-modal').find('.modal-content').css('height',$(window).height() + 80);
    //                     $('#game-fullscreen-modal').find('.info-box').html("");
    //                     $('#game-fullscreen-modal').find('.info-box').append('<iframe src="https://engage.devapp.co/games/'+target+'/" width="100%"  border="0"></iframe>')
    //                     $('#game-fullscreen-modal').find('iframe').css('height',$(window).height());
    //                     $('#game-fullscreen-modal').find('iframe').css('border',0);
    //                     $('#game-fullscreen-modal').modal('show');
    //                     $(window).resize(function(){
    //                         $('#game-fullscreen-modal').find('iframe').css('height',$(window).height());
    //                         $('#game-fullscreen-modal').find('iframe').css('width',$(window).width());
    //                         $('#game-fullscreen-modal').find('.modal-content').css('width',$(window).width());
    //                         $('#game-fullscreen-modal').find('.modal-content').css('height',$(window).height() + 80);
    //                     })
    //                   }
    //                   else{
    //                     $('.a_link').remove();
    //                     var a = document.createElement('a');
    //                     a.href = `/games/${target}/`;
    //                     a.className='a_link';
    //                     a.setAttribute('target', '_blank');
    //                     a.click();
    //                   }
    //                 },
    //             });
    //         });
    //         return;
    //     }

        $.ajax({
            url: `/games/${target}/`,
            headers: {
                "X-CSRFToken": csrftoken,
            },
            async: false,
            type: "get",
            data: {},
            error: function (value) {
                
                var {
                    responseText,
                    status
                } = value;
                if (status === 404) {
                    $("#games-notifications #games-notifications-title").text("GAME NOT FOUND");
                    $("#games-notifications #games-notifications-body").text("Game Not Found");
                }
              
                else if (status === 403) {
                    $("#games-notifications #games-notifications-title").text("Free Subscription");
                    $("#games-notifications #games-notifications-body").text(responseText);
                   
                 }
                else if (status === 410) {
                    $("#games-notifications #games-notifications-title").text("Premium Games");
                    $("#games-notifications #games-notifications-body").text(responseText);
                    
                    
                }
                else {
                    $("#games-notifications #games-notifications-title").text("Error");
                    $("#games-notifications #games-notifications-body").text("Something Went Wrong");
                }
                
                $("#games-notifications").modal({
                    show: true,
                    keyboard: true,
                    backdrop: true,
                });
               
            },
            success: function (value) {
                var isIOS = /(iphone)/i.test(navigator.userAgent);
                var isAnroid = navigator.userAgent.toLocaleLowerCase().indexOf("android") > -1;
               
                var isAnroid = navigator.userAgent.toLocaleLowerCase().indexOf("android") > -1;
                var isIpadPro = navigator.userAgent.indexOf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15")>-1 && navigator.userAgent.indexOf("AppleWebKit/605.1.15 (KHTML, like Gecko)")>-1;
                
               
               // if(isIOS || isAnroid || isIpadPro){
                //window.location.href=`/games/${target}/`;
                $('#game-fullscreen-modal').find('.modal-content').css('width',$(window).width());
                $('#game-fullscreen-modal').find('.modal-content').css('height',$(window).height() + 80);
                $('#game-fullscreen-modal').find('.info-box').html("");
                $('#game-fullscreen-modal').find('.info-box').append('<iframe class="'+ (target == 'solve_math' ? 'solvemath' : '') +'" src="/games/'+target+'/" width="100%"  border="0"></iframe>');
                
                //New:
                $('#game-fullscreen-modal').find('.modal-body').addClass(target);
                
                $('#game-fullscreen-modal').find('iframe').css('height',$(window).height());
                $('#game-fullscreen-modal').find('iframe').css('border',0);
                $('#game-fullscreen-modal').modal('show');
                $('#game-fullscreen-modal').addClass('show');
                $('#game-fullscreen-modal').show();
                $(window).resize(function(){
                    $('#game-fullscreen-modal').find('iframe').css('height',$(window).height());
                    $('#game-fullscreen-modal').find('iframe').css('width',$(window).width());
                    $('#game-fullscreen-modal').find('.modal-content').css('width',$(window).width());
                    $('#game-fullscreen-modal').find('.modal-content').css('height',$(window).height() + 80);
                })
             // }
            //   else{
            //     $('.a_link').remove();
            //     var a = document.createElement('a');
            //     a.href = `/games/${target}/`;
            //     a.className='a_link';
            //     a.setAttribute('target', '_blank');
            //     a.click();
            //   }
            },
        });
        
    });

    $("#upgrade-btn").on("click", function () {
        subscribe_api(username, 1, idservice, referrer=referrer, vault=self.client);
    });

    // if (is_complete_profile == false) {
       

    //     var now = new Date();
    //     var day = now.getDate();
    //     var month = now.getMonth()+1;
    //     var year = now.getFullYear();
        
    //     var seen_day = parseInt(is_created_now.split(' ')[1].split(',')[0]);
    //     var seen_month = months.indexOf(is_created_now.split(' ')[0])+1;
    //     var seen_year = is_created_now.split(',')[1];
    //     if(day==seen_day && month==seen_month && year==seen_year){
    //         var lastCheck = localStorage.getItem('last_profile_edit')
    //         if (!lastCheck) {
    //             localStorage.setItem('last_profile_edit', now.toString())
    //             openEditProfileModal()
    //         } else {
    //             const diffTime = Math.abs(now - new Date(lastCheck));
    //             var diffHours = diffTime / 1000 / 60 / 60;
    //             if (diffHours >= 24) {
    //                 localStorage.setItem('last_profile_edit', now.toString())
    //                 openEditProfileModal()
    //             }
    //         }
    //     }
        
        
    // }
});

function copyToClipboard(txt) {
    var m = document;
    txt = m.createTextNode(txt);
    var w = window;
    var b = m.body;
    b.appendChild(txt);
    if (b.createTextRange) {
        var d = b.createTextRange();
        d.moveToElementText(txt);
        d.select();
        m.execCommand('copy');
    } else {
        var d = m.createRange();
        var g = w.getSelection;
        d.selectNodeContents(txt);
        g().removeAllRanges();
        g().addRange(d);
        m.execCommand('copy');
        g().removeAllRanges();
    }
    txt.remove();
}

function countdownTimeStart(element) {
    if ($(element).attr("data-start")) {
        var startDate = (Date.parse($(element).attr("data-start"))) / 1000;
        var endDate = (Date.parse($(element).attr("data-end"))) / 1000;

        if (serverTime < startDate) {
            var x = setInterval(function () {
                var seconds = startDate - serverTime;
                var days = Math.floor(seconds / 24 / 60 / 60);
                var hoursLeft = Math.floor((seconds) - (days * 86400));
                var hours = Math.floor(hoursLeft / 3600);
                var minutesLeft = Math.floor((hoursLeft) - (hours * 3600));
                var minutes = Math.floor(minutesLeft / 60);
                var remainingSeconds = seconds % 60;
                var html = "";

                if (days) {
                    days = days.toString().length == 1 ? '0' + days : days;

                    if (days == 1) {
                        html += days + " Day, ";
                    } else {
                        html += days + " Days, ";
                    }
                }

                hours = hours.toString().length == 1 ? '0' + hours : hours;
                minutes = minutes.toString().length == 1 ? '0' + minutes : minutes;
                remainingSeconds = remainingSeconds.toString().length == 1 ? '0' + remainingSeconds : remainingSeconds;

                html += hours + ":" + minutes + ":" + remainingSeconds;
                $(element).html('Starts: '+html);

                if (seconds < 0) {
                    clearInterval(x);
                    $(element).html("EXPIRED");
                }
            }, 1000);
        }

        if (serverTime > startDate && serverTime < endDate) {
            $(element).html("Ongoing");
        }

        if (serverTime > endDate) {
            $(element).html("Expired");
        }
    }

    if ($(element).attr("data-date")) {
        var countDownDate = (Date.parse($(element).attr("data-date"))) / 1000;
        var x = setInterval(function () {
            var seconds = countDownDate - serverTime;
            var days = Math.floor(seconds / 24 / 60 / 60);
            var hoursLeft = Math.floor((seconds) - (days * 86400));
            var hours = Math.floor(hoursLeft / 3600);
            var minutesLeft = Math.floor((hoursLeft) - (hours * 3600));
            var minutes = Math.floor(minutesLeft / 60);
            var remainingSeconds = seconds % 60;
            var html = "";

            if ($(element).hasClass('full-timer')) {
                days = days.toString().length == 1 ? '0' + days : days;
                if (days == 1) {
                    html += days + " Day, ";
                } else {
                    html += days + " Days, ";
                }
                $(element).html('Starts: '+html);

                hours = hours.toString().length == 1 ? '0' + hours : hours;
                minutes = minutes.toString().length == 1 ? '0' + minutes : minutes;
                remainingSeconds = remainingSeconds.toString().length == 1 ? '0' + remainingSeconds : remainingSeconds;

                html += hours + ":" + minutes + ":" + remainingSeconds;
                $(element).html('Starts: '+html);

                if (seconds < 0) {
                    clearInterval(x);
                    $(element).html("EXPIRED");
                }
            } else {
                if (days) {
                    days = days.toString().length == 1 ? '0' + days : days;
                    if (days == 1) {
                        html += days + " Day";
                    } else {
                        html += days + " Days";
                    }
                    $(element).html(html);
                } else {
                    hours = hours.toString().length == 1 ? '0' + hours : hours;
                    minutes = minutes.toString().length == 1 ? '0' + minutes : minutes;
                    remainingSeconds = remainingSeconds.toString().length == 1 ? '0' + remainingSeconds : remainingSeconds;

                    html += hours + ":" + minutes + ":" + remainingSeconds;
                    $(element).html(html);

                    if (seconds < 0) {
                        clearInterval(x);
                        $(element).html("EXPIRED");
                    }
                }
            }
        }, 1000);
    }
}
function positiveNumber(input) {
    input = $(input);
    if (input.val().length > 0) {
        if (input.val() <= 0) {
            input.val('1');
        }
    }
}

function showInfoModal(title, body) {
    var modal = $("#info-modal");
    modal.find(".modal-title").html(title);
    modal.find(".info-box").html(body);
    modal.modal();
}

function showPurchaseModal(title, body) {
    var modal = $("#purchase-modal");
    modal.find(".modal-title").html(title);
    modal.find(".info-box").html(body);
    
    if(title=='Error!' || title=='Not Enough Coins!'){
        $('#purchase-btn').hide();
        modal.find("button").eq(1).text("OK");
    }
    else{
        $('#purchase-btn').show();
        modal.find(".info-box").html(body);
        modal.find("button").eq(1).text("Cancel");
    }
    modal.modal();
}


function resetStar(obj){
    var sectionName='';
    if($(obj).attr('id')=='hometournaments'){
      sectionName='tournaments';
    }
    else if($(obj).attr('id')=='homegames'){
      sectionName='games';
    }
    else if($(obj).attr('id')=='a-prize'){
      sectionName='prizes';
    }
    else if($(obj).attr('id')=='a-redeem'){
      sectionName='redeem';
    }
    else if($(obj).attr('id')=='li_winners'){
      sectionName='winners';
    }
    $.ajax({
      url: update_log.replace("user_uid", user_uid),
      headers: {
          "X-CSRFToken": xtoken,
      },
      type: "post",
      data: {section_name:sectionName},
      error: function (value) {
      },
      success: function (value) {
        $(obj).find('i').hide();
      },
  });
  
  }

  function checkSeenCoins(){
    $.ajax({
        url: check_usercoin.replace("user_uid", user_uid),
        headers: {
            "X-CSRFToken": xtoken,
        },
        type: "post",
        data: {},
        error: function (value) {
        },
        success: function (value) {
          if(value.redFlag==true){$('#user-coins').css('background','#EA2D2D');}
          else{ $('#user-coins').css('background','#650f5e');}
          
        }, 
    }) 
  }

var hasScrolledToTarget = false;
$(window).scroll(function() {
    if($('.homsec').length!=0){
    if (hasScrolledToTarget) return; 
      var targetOffset = $("#tournaments").offset().top;
      var scrollTop = $(window).scrollTop();
      if (targetOffset - scrollTop < 300 ) {
          hasScrolledToTarget = true; 
          myFunction();
          
      }
    }
    
});

function myFunction() {
   $('.firstTab').find('a').eq(0).click();
  }

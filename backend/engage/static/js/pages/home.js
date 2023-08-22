var mobileOS = mobilecheck();
if(mobileOS=='pc')
   $('body').addClass('desktop');


   
$(function () {







    
    $('.sec-3-1 .drp_tournament').selectize({
      sortField: 'text'
    });
    $('.sec-3-1 .drp_game').selectize({
      sortField: 'text'
    });
      
  // load winners on page load
  getWinners($('.drp_game').val(),$('.drp_tournament  .selectize-input').find('.item').attr('data-value'));
  $('.drp_game').on('change', function() {
    var value = $(this).val();
    if($('.drp_tournament .selectize-dropdown-content').find('.option').length==0){
      
      setTimeout(() => {
      $('.drp_tournament  .selectize-input').click();
      $('.drp_tournament  .selectize-dropdown').addClass('invisible');
      }, 500);






              
    }
     setTimeout(function(){
      $('.drp_tournament  .selectize-dropdown-content').find('.option').hide();
      var selected=false;
      $('.selectize-dropdown').removeClass('invisible');
      $('.hiddenTournament_select option').each(function(ind){
        var firstItem = $('.hiddenTournament_select option').eq(ind);
        if($('.drp_tournament  .selectize-dropdown-content').find('.option').length > 0){
          $('.drp_tournament  .selectize-dropdown-content').find('.option').each(function(ind1){
            if(value =='' || (value == firstItem.attr('game') &&  $('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).attr('data-value')==firstItem.attr('value'))){
      
              $('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).show();
              if(!selected)
              {
                $('.drp_tournament  .selectize-input').find('.item').attr('data-value', $('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).attr('data-value'));
                $('.drp_tournament  .selectize-input').find('.item').text($('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).text());
                selected=true;
              }
            }
          })
        }
        

   
      })




    
      getWinners($('.drp_game').val(), $('.drp_tournament  .selectize-input').find('.item').attr('data-value'));
      $('.sec-3-1 select.drp_tournament option').eq(0).attr("value",$('.drp_tournament  .selectize-input').find('.item').attr('data-value'));
      $('.sec-3-1 select.drp_tournament option').eq(0).text($('.drp_tournament .selectize-input').find('.item').text());
      $('.drp_tournament  .selectize-dropdown-content').find('.option').removeClass('selected').removeClass('active');
      $('.drp_tournament  .selectize-dropdown-content').find('.option[data-value='+$('.drp_tournament  .selectize-input').find('.item').attr('data-value')+']').addClass('selected').addClass('active');
      
      var valueTournament = $('.drp_tournament  .selectize-input').find('.item').attr('data-value');
      if(valueTournament == undefined)
            $(".loading-tr").find(".loading-img").hide();
     },500);
    
   







  });
  $('.sec-3-1 .drp_tournament').on('change', function() {
      setTimeout(function(){
        $('.drp_tournament  .selectize-input').find('.item').text($('.drp_tournament  .selectize-dropdown-content').find('.option.active').text());
        $('.drp_tournament  .selectize-input').find('.item').attr('data-value',$('.drp_tournament  .selectize-dropdown-content').find('.option.active').attr('data-value'));
        getWinners($('.drp_game').val(),$('.drp_tournament  .selectize-input').find('.item').attr('data-value'));





    
       var valueTournament = $('.drp_tournament  .selectize-input').find('.item').attr('data-value');
       if(valueTournament == undefined)
          $(".loading-tr").find(".loading-img").hide();
      },600)







               
    })
     $('.drp_tournament  .selectize-control').click(function(){
         var active = $('.drp_tournament.selectized').val();
          setTimeout(function(){
                 if(active==$('.drp_tournament  .selectize-dropdown-content').find('.option.active.selected').attr('data-value') || $('.drp_tournament  .selectize-dropdown-content').find('.option.active.selected').length==0)
                 return;
                 if($('.drp_tournament.selectized').val() != $('.drp_tournament  .selectize-dropdown-content').find('.option.active').attr('data-value')){
                  $('.drp_tournament  .selectize-input').find('.item').text($('.selectize-dropdown-content').find('.option.active').text());
                  $('.drp_tournament  .selectize-input').find('.item').attr('data-value',$('.drp_tournament  .selectize-dropdown-content').find('.option.active').attr('data-value'));
                  getWinners($('.drp_game').val(),$('.drp_tournament .selectize-input').find('.item').attr('data-value'));
                 }

          },700)
     });
  
  // load tournaments on page load
  $(".tour-btn").click();

  
  // add scroll for winners list
    $('.scroll_wrapper').css('width',($('.package').outerWidth(true) + 20)*$('.package').length + 'px');
  //




  
  //   make featured games in multiple rows (5 items in the columns)
  var f_games_parent = $(".featured-games-parent");
  var main_f_games = $("#main-featured-games");
  var f_games_items = $(main_f_games.find(".featured-item"));
  var new_item = $("<div></div>");
  new_item.attr("class", main_f_games.attr("class"));
  var mobileOS = mobilecheck();

    for (let i = 0; i < f_games_items.length; i++) {
    const item = $(f_games_items[i]);








    if (new_item.find(".featured-item").length < 5) {
      new_item.append(item);
      f_games_parent.append(new_item);
    } else {
      new_item = $("<div></div>");
      new_item.attr("class", main_f_games.attr("class"));
      f_games_parent.append(new_item);
      new_item.append(item);
    }
 
    const item_link = item.find("a");
    if (mobileOS === "android") {
      item_link.attr("href", item_link.data("link-android"));
    } else if (mobileOS === "ios") {
      item_link.attr("href", item_link.data("link-ios"));
    } else {
      item_link.attr("href", item_link.data("link-pc"));
    }
    }






















    // var swiper = new Swiper(".mySwiper", {
    //   breakpoints: {
    //     320: {
    //       slidesPerView: 3,
    //       spaceBetween: 40,
    //     },
    //     895: {
    //       slidesPerView: 4,
    //       spaceBetween: 40,
    //     },
    //     1024: {
    //       slidesPerView: 5,
    //       spaceBetween: 50,
    //     },
    //   },
    //   scrollbar: {
    //     el: ".swiper-scrollbar",
    //     draggable: true,
    //   },
// });

  //scroll to tournaments section or games section when user clicks the navbar links
  $("#hometournaments, #homegames,#li_winners").on("click", function () { //,#a-redeem,#a-prize
    hashchanged();
  });
});

function matchCustom(params, data) {
  // If there are no search terms, return all of the data
  if ($.trim(params.term) === '') {
    return data;
  }

  // Do not display the item if there is no 'text' property
  if (typeof data.text === 'undefined') {
    return null;
  }

  // `params.term` should be the term that is used for searching
  // `data.text` is the text that is displayed for the data object
  if (data.text.indexOf(params.term) > -1) {
    var modifiedData = $.extend({}, data, true);
    modifiedData.text += ' (matched)';

    // You can return modified objects from here
    // This includes matching the `children` how you want in nested data sets
    return modifiedData;
  }

  // Return `null` if the term should not be displayed
  return null;
}
$(".featured-item a").on("click", function(e) {
  if(!is_authenticated) {
    return
  }
  const featured_game_id = $(this).data('id');

  $.ajax({
      url: `${featured_game_retrieve}${featured_game_id}/`,
      headers: {},
      type: "get",
      success: function (data) {
        if(data.coins > 0){
          $('#user-coins').css('background','#EA2D2D');
        }
        const user_coins = parseInt($("#actual-user-coins").text()) + data.coins;
        $("#actual-user-coins, .user-coins").html(user_coins);
      },
  });
})

//handle upgrade subscription click
$("#upgrade-package-pgame-modal .modal-content").on("click", function () {
  setBtnLoading($(this), true);

  function upgrade_subsp() {
      return new Promise((resolve, reject) => {
          $.ajax({
              url: upgrade_subscription.replace("user_uid", user_uid),
              headers: {
                  "X-CSRFToken": xtoken,
              },
              type: "post",
              data: {},
              error: function (value) {
                  reject(value);
              },
              success: function (value) {
                  value.is_sub
                  resolve(value);
                  if (value.is_sub == 'false')
                  {
                    window.location.href="/secured"
                  }
                  else{
                    $("#upgrade-package-pgame-modal").modal("hide");
                    setBtnLoading($("#upgrade-package-pgame-modal"), false);
                    window.location.reload(true);
                  }
                  
              },
          });
      });
  }

  upgrade_subsp().then(function (_) {
      
      // $("#upgrade-package-pgame-modal").modal("hide");
      // setBtnLoading($("#upgrade-package-pgame-modal"), false);
      //window.location.reload(true);
  }).catch(function (error) {
    $("#upgrade-package-pgame-modal").modal("hide");
      setBtnLoading($("#upgrade-package-pgame-modal"), false);
      showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
  });
});

var tInt = setInterval(function(){

  if($('.st-btn[data-network="sms"]').length > 0){
    clearInterval(tInt);
    if(!(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent))){
      // true for not mobile device
     $('.st-btn[data-network="sms"]').attr("style", "display:none!important");
    }else{
      // false for  mobile device
      $('.st-btn[data-network="sms"]').attr("style", "display:inline-block!important");
    }
  }

},50);
 

//Tournaments:
//////////////////////////////////////////
$(window).on('load resize', function() {
  if($("#tournaments").length > 0){
//if(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent))
  var isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent); //navigator.userAgent.match(/(iPad)|(iPhone)|(iPod)|(android)|(webOS)/i);
  var height = $(window).height();
  var width = $(window).width();

  var ua = navigator.userAgent.toLowerCase();
  var isAndroid = ua.indexOf("android") > -1;
  
  if ((width > height && (isMobile || isAndroid)) || (isMobile || isAndroid)) {
      //run landscape script
      $("#tournament_dv").addClass("tobeMob");
      $("#tournament_dv").find(".mobileversion").show();
      $("#tournament_dv").find(".desktopversion").hide();

      $("#tournament_dv").find(".mobileversion").attr("style", "display:block!important");
      $("#tournament_dv").find(".desktopversion").attr("style", "display:none!important");

      var packs =  $("#tournament_dv").find(".mobileversion").find(".package"); 
      for(var i=0; i < packs.length; i++)
      {
        var nbNews = $(packs[i]).find(".newsbv-item").length;
        var minLen = nbNews * ($(packs[i]).find(".newsbv-item").eq(0).width() + 15); 
        //minLen = minLen+100;
        
        if(width > height)
          $(packs[i]).find(".list").attr("style", "width: "+(minLen + 140)+"px!important");
        else
          $(packs[i]).find(".list").attr("style", "width: "+(minLen)+"px!important");
        
   
      }

      $("#tournament_dv").attr("style","max-height: 7000px!important"); 

      

  } else {
      //run portrait script
      $("#tournament_dv").removeClass("tobeMob");

      $("#tournament_dv").find(".desktopversion").show();
      $("#tournament_dv").find(".mobileversion").hide();

      $("#tournament_dv").find(".desktopversion").attr("style", "display:block!important");
      $("#tournament_dv").find(".mobileversion").attr("style", "display:none!important");

      $("#tournament_dv").attr("style","max-height: 1116px!important");

       
  }

  if(width > height)
    $("body").addClass("land");
  else
    $("body").removeClass("land");
  //  alert("desktopversion: "+ $("#tournament_dv").find(".desktopversion").attr("style"));
  //  alert("mobileversion: "+ $("#tournament_dv").find(".mobileversion").attr("style"));
 // alert("body: "+ $('body').attr('class'));

}
});


//////////////////////////////////////////
 
// function showSocialLinks(){
//   $('.sharethis-inline-share-buttons').show();
//   $('.st-btn').attr("style", "display:inline-block");
//   if(!(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent))){
//     // true for not mobile device
//    $('.st-btn[data-network="sms"]').attr("style", "display:none");
//   }else{
//     // false for  mobile device
//     $('.st-btn[data-network="sms"]').attr("style", "display:inline-block");
//   }
// }

// function hideSocialLinks(){
//   $('.sharethis-inline-share-buttons').hide();
//   $('.st-btn').attr("style", "display:none");
//   $('.st-btn[data-network="sms"]').attr("style", "display:none");
// }
 
// $(document).on('click', function (e) {
//   if (!$(e.target).hasClass('sharethis-inline-share-buttons') && !$(e.target).hasClass('st-btn') && !$(e.target).hasClass('scl') && !$(e.target).hasClass('aitem')
//   && !$(e.target).hasClass('slid-item') && !$(e.target).hasClass('slick-slide') && !$(e.target).hasClass('small_btn')) {
//     hideSocialLinks();
//   }
// });

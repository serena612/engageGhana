$(function () {
  var csrftoken = xtoken;
  var isIphone = (/iphone/i.test(navigator.userAgent) || /ipod/i.test(navigator.userAgent)) && !this.isIE && !this.isMicrosoftEdge;
 
//   function callOncePerDay(user) {
//   var lastCalled = localStorage.getItem('lastCalled_'+ user );
//   var now = new Date().getTime();
  

//   if (!lastCalled || (now - lastCalled > 24 * 60 * 60 * 1000)) {
    
//     localStorage.setItem('lastCalled_'+user, now);
//     if($('#go-premium-modal').length!=0){
//     $('#go-premium-modal').modal('show');
//     go_premium_sent.go_premium_sent = true
//     }
//   }
// }

function callOncePerDay(user) {
  var lastCalled = localStorage.getItem('lastCalled_'+ user );
  var now = new Date();

  // Get the start of the current day by setting the hours, minutes, seconds, and milliseconds to zero
  var startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  if (!lastCalled || (new Date(lastCalled) < startOfDay)) {
    localStorage.setItem('lastCalled_'+user, now);
    if($('#go-premium-modal').length!=0){
      $('#go-premium-modal').modal('show');
      return new Promise((resolve, reject) => {
        $.ajax({
          url: update_go_premium_flag.replace("user_uid", user_uid),
          headers: {
            "X-CSRFToken": xtoken,
          },
          type: "post",
          data: {},
          error: function (value) {
              reject(value);
          },
          success: function (value) {
              resolve(value);
            },
        });
      });
    }
  }
}

$(document).ready(function(){
      if (user_uid){
        callOncePerDay(user_uid);
        $(".li_go_premium,#go-premium-modal .btn_upgrade").on("click", function () {
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
                    
                      },
                  });
              });
          }
        
          upgrade_subsp().then(function (_) {
          }).catch(function (error) {
              showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
          });
        });
      }
})
  
  var firebaseConfig = {
    apiKey: "AIzaSyClFi6oYdwKrbbTYBSNRdbYmLXJ4uR-vHI",
    authDomain: "engageplaywin-4b74b.firebaseapp.com",
    projectId: "engageplaywin-4b74b",
    storageBucket: "engageplaywin-4b74b.appspot.com",
    messagingSenderId: "729860295401",
    appId: "1:729860295401:web:b732dc0c7618190cf53e78",
    measurementId: "G-C0XVDBF16H"
  };
  
  var firebaseApp =firebase.initializeApp(firebaseConfig);
  var messaging = firebase.messaging(firebaseApp);
  // const analytics = getAnalytics();
  // logEvent(analytics, 'screen_view', {
  //   firebase_screen: screenName, 
  //   firebase_screen_class: screenClass
  // });
  var current_early_notifications_page = 1;
  var early_notifications_has_next = false;
  var loading = false;
  var popupsToLoad=0;
  var totalNews=0;

  var myInterval;
  var interval_delay = 60000;
  var is_interval_running = false; //Optional
  var is_active = false;
 
  var defaultlang="en-us";
  var lang = lang_code;
  console.log("lang",lang);
  

  function adjustSettingPopNum(obj){
    $("#notifications-popup").find("#notification-popup-"+obj.notification.id).modal({
      show: true,
      keyboard: true,
      backdrop: true,
    });
   
    $("#notifications-popup").find("#notification-popup-"+obj.notification.id).on('hidden.bs.modal', function () {
      updateNotificationStatus(obj.id);
      popupsToLoad--;
      if(popupsToLoad > 0)
      adjustSettingPopNum(totalNews[(totalNews.length-popupsToLoad)]);

      var notificationsCount = $("#notifications-count").text();
      if (notificationsCount.length >= 1) {
        notificationsCount = parseInt(notificationsCount);
        $("#notifications-count").text(
          `${notificationsCount > 0 ? notificationsCount - 1 : 0}`
        );
        if(notificationsCount > 1)
          $('#notifications-count').css('background','#EA2D2D');
        else 
          $('#notifications-count').css('background','#650f5e');   
      }
      else if (notificationsCount.length == 0)
        $('#notifications-count').css('background','#650f5e');
     
    })
  }
  function loadUnreadPopups(){
    // getNewEarlyNotifications().then(function (result) {
    //   // set notifications badge >> count
    //   $("#notifications-count").text(`${result.length}`);

    //   if (result.length >= 1) {
    //     $('#notifications-count').css('background','#EA2D2D');
    //     // re-append the notifications
    //     //$("#notification-list").append(`
    //       //<li class="header-noti">
    //       //    <h5>New</h5>
    //       //</li>
    //  // `);

    //     result.map((i) => {
    //       var className='new-notification';
    //       if(i.last_read !=null && i.last_read !="" && i.last_read !=undefined ){
    //         className='earlier-notification';
    //       }
          
    //       if (i.notification.action == "text" && i.friend_uid == undefined && i.notification.template=='user_register_for_tournament') {
    //         $("#notification-list").append(`
    //         <li class="`+className+`">
    //             <a
    //               id="${i.notification.id}"
    //               data-id="${i.id}"
    //               url="${i.link}"
    //               action="${i.notification.action}"
    //               class="notification"
    //             >
    //                 <span class="title">${i.title}</span>
    //                 <span class="desc">${i.text}</span>
    //                 <span class="date">${moment(i.created).format(
    //                   "MMMM DD YYYY, h:mm:ss a"
    //                 )}</span>
    //             </a>
    //         </li>
    //     `);
    //       } 
    //       else if (i.notification.action == "text" && i.friend_uid == undefined && (i.notification.template=='before_match_informative' || i.notification.template=='win_match_informative')) {
    //         $("#notification-list").append(`
    //         <li class="`+className+`">
    //             <a
    //               id="${i.notification.id}"
    //               data-id="${i.id}"
    //               url="${i.link}"
    //               action="${i.notification.action}"
    //               class="notification"
    //             >
    //                 <span class="title">${i.title}</span>
    //                 <span class="desc">${i.text}</span>
    //                 <span class="date">${moment(i.created).format(
    //                   "MMMM DD YYYY, h:mm:ss a"
    //                 )}</span>
    //             </a>
    //         </li>
    //     `);
    //       } 
    //       else if (i.notification.action == "text" && i.friend_uid == undefined) {
    //         /////////////////////////////////////////////////////////
    //         if(i.notification.template == "complete_profile")
    //         {
    //             var profileUrl = $('.nav-my-profile').attr('href');
    //             $("#notification-list").append(`
    //             <li class="`+className+`">
    //                 <a
    //                   id="${i.notification.id}"
    //                   data-id="${i.id}"
    //                   url="${i.notification.url}"
    //                   action="${i.notification.action}"
    //                   onclick="openEditProfileModal(event)"                      
    //                   class="notification"
    //                 >
    //                     <span class="title">${i.title}</span>  
    //                     <span class="desc">${i.text}</span>
    //                     <span class="date">${moment(i.created).format(
    //                       "MMMM DD YYYY, h:mm:ss a"
    //                     )}</span>
    //                 </a>
    //             </li>
    //         `);            
    //         }else{
    //           console.log("here ");

    //           if(i.notification.url && i.notification.url.indexOf('#home-tournaments') != -1)
    //           {
    //             console.log("here 1");
    //         $("#notification-list").append(`
    //         <li class="`+className+`">
    //             <a
    //               id="${i.notification.id}"
    //               data-id="${i.id}"
    //               url="${i.notification.url}"
    //               action="${i.notification.action}"
    //               class="notification" onclick="$('.tab-link.tour-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);"
    //             >
    //                 <span class="title">${i.title}</span>
    //                 <span class="desc">${i.text}</span>
    //                 <span class="date">${moment(i.created).format(
    //                   "MMMM DD YYYY, h:mm:ss a"
    //                 )}</span>
    //             </a>
    //         </li>
    //     `);
    //                 }
    //                 else if(i.notification.url && i.notification.url.indexOf('#home-games') != -1)
    //                 {
                       
    //               $("#notification-list").append(`
    //               <li class="`+className+`">
    //                   <a
    //                     id="${i.notification.id}"
    //                     data-id="${i.id}"
    //                     url="${i.notification.url}"
    //                     action="${i.notification.action}"
    //                     class="notification" onclick="$('.games-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);"
    //             >
    //                 <span class="title">${i.title}</span>
    //                 <span class="desc">${i.text}</span>
    //                 <span class="date">${moment(i.created).format(
    //                   "MMMM DD YYYY, h:mm:ss a"
    //                 )}</span>
    //             </a>
    //         </li>
    //     `);
    //                 }
    //                 else{
    //         $("#notification-list").append(`
    //         <li class="`+className+`">
    //             <a
    //               id="${i.notification.id}"
    //               data-id="${i.id}"
    //               url="${i.notification.url}"
    //               action="${i.notification.action}"
    //               class="notification"
    //             >
    //                 <span class="title">${i.title}</span>
    //                 <span class="desc">${i.text}</span>
    //                 <span class="date">${moment(i.created).format(
    //                   "MMMM DD YYYY, h:mm:ss a"
    //                 )}</span>
    //             </a>
    //         </li>
    //     `);

    //                 }

              
    //         }

    //       } 
    //       else {
    //         var friend_request = i.friend_uid
    //           ? `
    //       <div class="col-md-12">
    //       <div id="accept-new-friend" target="${i.friend_uid}" class="btn2 big" >Accept</div>
    //       <button id="reject-new-friend" target="${i.friend_uid}" class="btn2 big" >Reject</button>
    //       </div>
    //       `
    //           : "";

    //         $("#notification-list").append(`
    //         <li class="`+className+`">
    //             <p 
    //               id="${i.notification.id}"
    //               data-id="${i.id}"
    //               action="${i.notification.action}"
    //               class="notification"
    //             >
    //                 <span class="title">${i.title}</span>
    //                 <span class="desc">${i.text}</span>

    //                 ${friend_request}

    //                 <span class="date">${moment(i.created).format(
    //                   "MMMM DD YYYY, h:mm:ss a"
    //                 )}</span>
    //             </p>
    //         </li>
    //     `);
    //       }

    //       if (i.notification.action == "video") {
    //         if (i.notification.video) {
    //           $("#notifications-popup").append(`
    //             <div class="modal fade" id="notification-popup-${
    //               i.notification.id
    //             }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
    //             i.notification.id
    //           }Label" aria-hidden="true">
    //               <div class="modal-dialog" role="document">

    //                 <div class="modal-content">
    //                   <div class="modal-header">
    //                     <h5 class="modal-title" id="notification-popup-${
    //                       i.notification.id
    //                     }Label">${i.title}</h5>
    //                   </div>
    //                   <div class="modal-body">
    //                     <p class="text-center">${i.text}</p>
    //                     <video
    //                     gift-id="${i.notification.id}"
    //                     gifted-coins="${i.notification.gifted_coins}"
    //                     id="${
    //                       i.notification.is_gift && !i.notification.is_claimed
    //                         ? `engage-gift-${i.notification.id}`
    //                         : `engage-player`
    //                     }"
    //                     class="video-js"
    //                     preload="auto"
    //                     poster="/static/img/top-logo.png"
    //                     data-setup='{}'>
    //                       <source src="${
    //                         i.notification.video
    //                       }" type="video/${i.notification.video
    //             .split(/[#?]/)[0]
    //             .split(".")
    //             .pop()
    //             .trim()}"></source>
    //                       <p class="vjs-no-js">
    //                         To view this video please enable JavaScript, and consider upgrading to a
    //                         web browser that
    //                         <a href="https://videojs.com/html5-video-support/" target="_blank">
    //                           supports HTML5 video
    //                         </a>
    //                       </p>
    //                     </video>
    //                   </div>
    //                 </div>

    //               </div>
    //             </div>
    //           `);
    //         }
    //       }
    //         if (i.notification.action == "image" && i.is_popup && i.last_read==null) {

    //         var image = (i.notification.translations[lang]==undefined)?i.notification.translations[defaultlang].image:i.notification.translations[lang].image;
        
    //         if (
    //           image &&
    //           i.notification.is_gift &&
    //           !i.notification.is_claimed
    //         ) {
    //           $("#notifications-popup").append(`
    //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
    //           <div class="modal-dialog" role="document">

    //             <div class="modal-content">
    //               <div class="modal-header">
    //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
    //               </div>
    //               <div class="modal-body">
    //                 <p class="text-center">${i.text}</p>
    //                 <a
    //                 id="${i.notification.id}"
    //                 gifted_coins="${i.notification.gifted_coins}"
    //                 class="claim-gift"
    //               >
    //                 <img
    //                 class="notification-img"
    //                   src="${image}"
    //                 />
    //               </a>
    //               </div>
    //             </div>

    //           </div>
    //         </div>
    //       `);
    //         } else if (image) {
    //           var index=0;var tournament_name="";var prize_name="";var prize_image="";
    //           if(i.link!=null && i.link.indexOf(';')>0){
    //             tournament_name=i.link.split(';')[0].replace('"','');
    //             prize_name=i.link.split(';')[1];
    //             prize_image='/media/'+i.link.split(';')[2];
    //           }
            
    //           if(i.notification.template == 'user_first_tournament'){
    //           index=1;
    //           }
    //           else if(i.notification.template == 'user_second_third_tournament'){
    //           index=2;
    //           }
    //           else if(i.notification.template=='user_outside_the_winning_positions'){
    //             index=3;
    //           }
    //           else if(i.notification.template=='complete_profile'){
    //             index=4;
    //           }
    //           $("#notifications-popup").append(`
    //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
    //           <div class="modal-dialog" role="document">

    //             <div class="modal-content">
    //               <div class="modal-header">
    //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
    //               </div>
    //               <div class="modal-body">
    //                 <p class="text-center">${i.text} </p>
    //                 <img
    //                 class="notification-img" onclick="openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
    //                   src="${image}" />
    //               </div>
    //             </div>

    //           </div>
    //         </div>
    //       `);
    //         } else {
    //           $("#notifications-popup").append(`
    //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
    //           <div class="modal-dialog" role="document">

    //             <div class="modal-content">
    //               <div class="modal-header">
    //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
    //               </div>
    //               <div class="modal-body">
    //                 <p class="text-center">${i.text}</p>
    //               </div>
    //             </div>
    //           </div>
    //         </div>
    //       `);
    //         }
    //       }
    //     });
    //   }
    //   else{
    //     $('#notifications-count').css('background','#650f5e');
    //   }
    // });
    getNewEarlyNotifications().then(function (result) {
        if(result.length >0){
          var newresult = result.filter(function(i){ 
            return ((i.notification.action == "video" && i.is_popup && i.last_read==null) || (i.notification.action == "image" && i.is_popup && i.last_read==null));
          });
          if(newresult.length >0){
          totalNews=newresult;
          popupsToLoad=newresult.length;
          newresult.map((i) => {
            if (i.notification.action == "video" && i.is_popup && i.last_read==null) {
              if (i.notification.video) {
                $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${
                    i.notification.id
                  }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
                  i.notification.id
                }Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">

                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${
                            i.notification.id
                          }Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text}</p>
                          <video
                          gift-id="${i.notification.id}"
                          gifted-coins="${i.notification.gifted_coins}"
                          id="${
                            i.notification.is_gift && !i.notification.is_claimed
                              ? `engage-gift-${i.notification.id}`
                              : `engage-player`
                          }"
                          class="video-js"
                          preload="auto"
                          poster="/static/img/top-logo.png"
                          data-setup='{}'>
                            <source src="${
                              i.notification.video
                            }" type="video/${i.notification.video
                  .split(/[#?]/)[0]
                  .split(".")
                  .pop()
                  .trim()}"></source>
                            <p class="vjs-no-js">
                              To view this video please enable JavaScript, and consider upgrading to a
                              web browser that
                              <a href="https://videojs.com/html5-video-support/" target="_blank">
                                supports HTML5 video
                              </a>
                            </p>
                          </video>
                        </div>
                      </div>

                    </div>
                  </div>
                `);
              }
            }
            if (i.notification.action == "image" && i.is_popup && i.last_read==null) {
              var image = (i.notification.translations[lang]==undefined)?i.notification.translations[defaultlang].image:i.notification.translations[lang].image;
        
              if (
                image &&
                i.notification.is_gift &&
                !i.notification.is_claimed
              ) {
                $("#notifications-popup").append(`
              <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                <div class="modal-dialog" role="document">

                  <div class="modal-content">
                    <div class="modal-header">
                      <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                    </div>
                    <div class="modal-body">
                      <p class="text-center">${i.text}</p>
                      <a
                      id="${i.notification.id}"
                      gifted_coins="${i.notification.gifted_coins}"
                      class="claim-gift"
                    >
                      <img
                      class="notification-img"
                        src="${image}"
                      />
                    </a>
                    </div>
                  </div>

                </div>
              </div>
            `);
              } else if (image) {
                var index=0;var tournament_name="";var prize_name="";var prize_image="";
                if(i.link!=null && i.link.indexOf(';')>0){
                  tournament_name=i.link.split(';')[0].replace('"','');
                  prize_name=i.link.split(';')[1];
                  prize_image='/media/'+i.link.split(';')[2];
                }
              
                if(i.notification.template == 'user_first_tournament'){
                index=1;
                }
                else if(i.notification.template == 'user_second_third_tournament'){
                index=2;
                }
                else if(i.notification.template=='user_outside_the_winning_positions'){
                  index=3;
                }
                else if(i.notification.template=='complete_profile'){
                  index=4;
                }
                $("#notifications-popup").append(`
              <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                <div class="modal-dialog" role="document">

                  <div class="modal-content">
                    <div class="modal-header">
                      <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                    </div>
                    <div class="modal-body">
                      <p class="text-center">${i.text} </p>
                      <img
                      class="notification-img" onclick="openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
                        src="${image}" />
                    </div>
                  </div>

                </div>
              </div>
            `);
              } else {
                $("#notifications-popup").append(`
              <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                <div class="modal-dialog" role="document">

                  <div class="modal-content">
                    <div class="modal-header">
                      <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                    </div>
                    <div class="modal-body">
                      <p class="text-center">${i.text}</p>
                    </div>
                  </div>
                </div>
              </div>
            `);
              }
            }
          });
          adjustSettingPopNum(totalNews[0])
        }
       }
      })
  }
  function sendNewUserNotification(payload){
    $.ajax({
      url: get_user_notifications_url,
      headers: {
        "X-CSRFToken": csrftoken,
      },
      type: "get",
      data: {
        title:payload.title,
        body:payload.body
      },
      error: function (value) {
       
      },
      success: function (value) {
        console.log('value',value);
       // if(value.notification.is_popup==true){
          navigator.serviceWorker.ready
          .then((registration) => {
            registration.showNotification(value.title, {
              body: value.text,
              icon: "/static/img/notification-icon.png",
            });
          })
          .catch((error) => {
            console.log(error);
          });
      //  }
      
      },
    });
  }

  
  function getNewEarlyNotifications() {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: get_new_early_notifications_url,
        headers: {
          "X-CSRFToken": csrftoken,
        },
        type: "get",
        data: {},
        error: function (value) {
          reject(value);
        },
        success: function (value) {
          resolve(value);
        },
      });
    });
  }

  // get all notifications that has not been read
  function getNewNotifications() {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: get_new_notifications_url,
        headers: {
          "X-CSRFToken": csrftoken,
        },
        type: "get",
        data: {},
        error: function (value) {
          reject(value);
        },
        success: function (value) {
          resolve(value);
        },
      });
    });
  }
 

  // get my coins value
  function getMyCoins() {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: get_my_coins,
        headers: {
          "X-CSRFToken": csrftoken,
        },
        type: "get",
        data: {},
        error: function (value) {
          reject(value);
        },
        success: function (value) {
          resolve(value);
        },
      });
    });
  }

  // get all notifications that has been read
  function getEarlyNotifications() {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: get_early_notifications_url,
        headers: {
          "X-CSRFToken": csrftoken,
        },
        type: "get",
        data: {
          page: current_early_notifications_page,
        },
        error: function (value) {
          reject(value);
        },
        success: function (value) {
          resolve(value);
        },
      });
    });
  }

  // set notification as has been read
  function updateNotificationStatus(notification_id) {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: set_notification_status_url,
        headers: {
          "X-CSRFToken": csrftoken,
        },
        type: "post",
        data: {
          id: notification_id,
        },
        error: function (value) {
          reject(value);
        },
        success: function (value) {
          resolve(value);
        },
      });
    });
  }

  function readAllNotifications() {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: read_all_notifications_url,
        headers: {
          "X-CSRFToken": csrftoken,
        },
        type: "post",
        error: function (value) {
          reject(value);
        },
        success: function (value) {
          console.log('value',value);
          $('#user-coins').text(value.coins);
          resolve(value);
        },
      });
    });
  }

  //Read all
  $('.rall').click(function() {
    console.log("read all clicked");
    $(".notification-dropdown").removeClass("show-notification");

    var notificationsCount = $("#notifications-count").text();

    
    notificationsCount = parseInt(notificationsCount);
    $("#notifications-count").text(
        `${notificationsCount > 0 ? 0 : 0}`
      );
    
    readAllNotifications();
    $(this).removeClass('new-notification').addClass('earlier-notification');
    $('#notifications-count').css('background','#800080');
  });
  
  // on notification clicked
  $(".notification-dropdown").on("click", ".notification", function () {
    $(".notification-dropdown").removeClass("show-notification");

    var notificationsCount = $("#notifications-count").text();

    if (notificationsCount.length >= 1 && $(this).parents('.new-notification').length!=0) {
      notificationsCount = parseInt(notificationsCount);
      $("#notifications-count").text(
        `${notificationsCount > 0 ? notificationsCount - 1 : 0}`
      );
      if(notificationsCount > 1)
        $('#notifications-count').css('background','#EA2D2D');
      else 
        $('#notifications-count').css('background','#650f5e');   
    }
    else if (notificationsCount.length == 0)
      $('#notifications-count').css('background','#650f5e');
    

    var notification_id = $(this).attr("id");
    var action = $(this).attr("action");

    if (action === "image" || action === "video") {
      $(`#notification-popup-${notification_id}`).modal({
        show: true,
        keyboard: true,
        backdrop: true,
      });
    } else if (action === "text") {
      var url = $(this).attr("url");

      if (url && url !== null && url !== "null" && url.length >= 1) {
        window.open(url, "_self").focus();
      }
      getAllNotifications();
    }

    const notificationId = $(this).data("id");
    updateNotificationStatus(notificationId);
    
    $(this).removeClass('new-notification').addClass('earlier-notification');
    $(".notification-dropdown").removeClass("show-notification");
    //getAllNotifications();

  });

  // on notifications list >> scroll to bottom
  $("#notification-list").on("scroll", function () {
    if (!loading) {
      var scrollTop = $(this).scrollTop();

      if (scrollTop + $(this).innerHeight() * 2 >= this.scrollHeight) {
        // end reached
        if (early_notifications_has_next) {
          loading = true;

          getEarlyNotifications().then(function (result) {
            if (result.pagination.has_next) {
              early_notifications_has_next = true;
              current_early_notifications_page += 1;
            } else {
              early_notifications_has_next = false;
            }

            if (result.data.length >= 1) {
              result.data.map((i) => {
                if (
                  i.notification.action == "text" &&
                  i.friend_uid == undefined  && i.notification.template=='user_register_for_tournament'
                ) {
                  $("#notification-list").append(`
                  <li class="earlier-notification 1">
                      <p id="${i.notification.id}" data-id="${i.id}" url="${
                    i.link
                  }" action="${i.notification.action}" class="notification">
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </p>
                  </li>
              `);
                }
                else if (
                  i.notification.action == "text" &&
                  i.friend_uid == undefined  && (i.notification.template=='before_match_informative' || i.notification.template=='win_match_informative')
                ) {
                  $("#notification-list").append(`
                  <li class="earlier-notification 2">
                      <p id="${i.notification.id}" data-id="${i.id}" url="${
                    i.link
                  }" action="${i.notification.action}" class="notification">
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </p>
                  </li>
              `);
                }
                else if (
                  i.notification.action == "text" &&
                  i.friend_uid == undefined  
                ) {
                  $("#notification-list").append(`
                  <li class="earlier-notification 3">
                      <p id="${i.notification.id}" url="${
                    i.notification.url
                  }" action="${i.notification.action}" class="notification">
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </p>
                  </li>
              `);
                }
                else {
                  var friend_request = i.friend_uid
                    ? `
                  <div class="col-md-12">
                    <div id="accept-new-friend" target="${i.friend_uid}" class="btn2 big" >Accept</div>
                    <button id="reject-new-friend" target="${i.friend_uid}" class="btn2 big" >Reject</button>
                  </div>
                  `
                    : "";

                  $("#notification-list").append(`
                  <li class="earlier-notification 4">
                      <p id="${i.notification.id}" action="${
                    i.notification.action
                  }" class="notification">
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          ${friend_request}

                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </p>
                  </li>
              `);
                }

                if (i.notification.action == "video") {
                  if (i.notification.video) {
                    $("#notifications-popup").append(`
                      <div class="modal fade" id="notification-popup-${
                        i.notification.id
                      }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
                      i.notification.id
                    }Label" aria-hidden="true">
                        <div class="modal-dialog" role="document">
      
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="notification-popup-${
                                i.notification.id
                              }Label">${i.title}</h5>
                            </div>
                            <div class="modal-body">
                              <p class="text-center">${i.text}</p>
                              <video
                              gift-id="${i.notification.id}"
                              gifted-coins="${i.notification.gifted_coins}"
                              id="${
                                i.notification.is_gift &&
                                !i.notification.is_claimed
                                  ? `engage-gift-${i.notification.id}`
                                  : `engage-player`
                              }"
                              class="video-js"
                              preload="auto"
                              poster="/static/img/top-logo.png"
                              data-setup='{}'>
                                <source src="${
                                  i.notification.video
                                }" type="video/${i.notification.video
                      .split(/[#?]/)[0]
                      .split(".")
                      .pop()
                      .trim()}"></source>
                                <p class="vjs-no-js">
                                  To view this video please enable JavaScript, and consider upgrading to a
                                  web browser that
                                  <a href="https://videojs.com/html5-video-support/" target="_blank">
                                    supports HTML5 video
                                  </a>
                                </p>
                              </video>
                            </div>
                          </div>
      
                        </div>
                      </div>
                    `);
                  }
                }

                if (i.notification.action == "image") {
                  var image = (i.notification.translations[lang]==undefined)?i.notification.translations[defaultlang].image:i.notification.translations[lang].image;
                  if (
                    image &&
                    i.notification.is_gift &&
                    !i.notification.is_claimed
                  ) {
                    
                    
                    $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">
      
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text}   </p>
                          <a
                          id="${i.notification.id}"
                          gifted_coins="${i.notification.gifted_coins}"
                          class="claim-gift"
                          >
                            <img
                              class="notification-img"
                              src="${image}"
                            />
                          </a>
                        </div>
                      </div>
      
                    </div>
                  </div>
                `);
                  } else if (image) {
                    var index=0;var tournament_name="";var prize_name="";var prize_image="";
                    if(i.link!=null && i.link.indexOf(';')>0){
                      tournament_name=i.link.split(';')[0].replace('"','');
                      prize_name=i.link.split(';')[1];
                      prize_image='/media/'+i.link.split(';')[2];
                    }
                  
                    if(i.notification.template == 'user_first_tournament'){
                    index=1;
                    }
                    else if(i.notification.template == 'user_second_third_tournament'){
                    index=2;
                    }
                    else if(i.notification.template=='user_outside_the_winning_positions'){
                      index=3;
                    }
                    else if(i.notification.template=='complete_profile'){
                      index=4;
                    }
                    $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">
      
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text} </p>
                          <img
                          class="notification-img" onclick="openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
                            src="${image}" />
                        </div>
                      </div>
                    </div>
                  </div>
                `);
                  } else {
                    $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">
      Reject
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text}</p>
                        </div>
                      </div>
      
                    </div>
                  </div>
                `);
                  }
                }
              });
            }

            loading = false;
          });
        }
      }
    }
  });

  const getAllNotifications = () => {
    if (!loading) {
      loading = true;
      current_early_notifications_page = 1;

      // reset the notifications list
      $("#notification-list").empty();
      $("#notifications-popup").empty();

      // re-append the notifications
      $("#notification-list").append(`
          <div class="d-flex flex-row justify-content-center align-items-center align-content-center" style="height: 200px;">
            <div class="align-self-center spinner-grow text-dark" role="status"></div>
          </div>
      `);

      $("#notification-list").empty();

      getNewEarlyNotifications().then(function (result) {
            // set notifications badge >> count
            var allread = result.filter(function(i) {
              return i.last_read == null 
            });
            console.log("allread",allread)    
            
            $("#notifications-count").text(`${allread.length}`);
            
            if (result.length >= 1) {
              $('#notifications-count').css('background','#EA2D2D');
              // re-append the notifications
              //$("#notification-list").append(`
                //<li class="header-noti">
                //    <h5>New</h5>
                //</li>
           // `);
    
              result.map((i) => {
                var className='new-notification';
                console.log("className", className)
                console.log("last read",i.last_read)
                console.log("i",i)

                
                if(i.last_read !=null && i.last_read !="" && i.last_read !=undefined ){
                  className='earlier-notification';
                }
                
                if (i.notification.action == "text" && i.friend_uid == undefined && i.notification.template=='user_register_for_tournament') {
                  $("#notification-list").append(`
                  <li class="`+className+`">
                      <a
                        id="${i.notification.id}"
                        data-id="${i.id}"
                        url="${i.link}"
                        action="${i.notification.action}"
                        class="notification"
                      >
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </a>
                  </li>
              `);
                } 
                else if (i.notification.action == "text" && i.friend_uid == undefined && (i.notification.template=='before_match_informative' || i.notification.template=='win_match_informative')) {
                  $("#notification-list").append(`
                  <li class="`+className+`">
                      <a
                        id="${i.notification.id}"
                        data-id="${i.id}"
                        url="${i.link}"
                        action="${i.notification.action}"
                        class="notification"
                      >
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </a>
                  </li>
              `);
                } 
                else if (i.notification.action == "text" && i.friend_uid == undefined) {
                  /////////////////////////////////////////////////////////
                  if(i.notification.template == "complete_profile")
                  {
                      var profileUrl = $('.nav-my-profile').attr('href');
                      $("#notification-list").append(`
                      <li class="`+className+`">
                          <a
                            id="${i.notification.id}"
                            data-id="${i.id}"
                            url="${i.notification.url}"
                            action="${i.notification.action}"
                            onclick="openEditProfileModal(event)"                      
                            class="notification"
                          >
                              <span class="title">${i.title}</span>  
                              <span class="desc">${i.text}</span>
                              <span class="date">${moment(i.created).format(
                                "MMMM DD YYYY, h:mm:ss a"
                              )}</span>
                          </a>
                      </li>
                  `);            
                  }else{
                    console.log("here ");
    
                    if(i.notification.url && i.notification.url.indexOf('#home-tournaments') != -1)
                    {
                      console.log("here 1");
                  $("#notification-list").append(`
                  <li class="`+className+`">
                      <a
                        id="${i.notification.id}"
                        data-id="${i.id}"
                        url="${i.notification.url}"
                        action="${i.notification.action}"
                        class="notification" onclick="$('.tab-link.tour-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);"
                      >
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </a>
                  </li>
              `);
                          }
                          else if(i.notification.url && i.notification.url.indexOf('#home-games') != -1)
                          {
                             
                        $("#notification-list").append(`
                        <li class="`+className+`">
                            <a
                              id="${i.notification.id}"
                              data-id="${i.id}"
                              url="${i.notification.url}"
                              action="${i.notification.action}"
                              class="notification" onclick="$('.games-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);"
                      >
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </a>
                  </li>
              `);
                          }
                          else{
                  $("#notification-list").append(`
                  <li class="`+className+`">
                      <a
                        id="${i.notification.id}"
                        data-id="${i.id}"
                        url="${i.notification.url}"
                        action="${i.notification.action}"
                        class="notification"
                      >
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </a>
                  </li>
              `);
    
                          }
    
                    
                  }
    
                } 
                else {
                  var friend_request = i.friend_uid
                    ? `
                <div class="col-md-12">
                <div id="accept-new-friend" target="${i.friend_uid}" class="btn2 big" >Accept</div>
                <button id="reject-new-friend" target="${i.friend_uid}" class="btn2 big" >Reject</button>
                </div>
                `
                    : "";
    
                  $("#notification-list").append(`
                  <li class="`+className+`">
                      <p 
                        id="${i.notification.id}"
                        data-id="${i.id}"
                        action="${i.notification.action}"
                        class="notification"
                      >
                          <span class="title">${i.title}</span>
                          <span class="desc">${i.text}</span>
    
                          ${friend_request}
    
                          <span class="date">${moment(i.created).format(
                            "MMMM DD YYYY, h:mm:ss a"
                          )}</span>
                      </p>
                  </li>
              `);
                }
    
                if (i.notification.action == "video") {
                  if (i.notification.video) {
                    $("#notifications-popup").append(`
                      <div class="modal fade" id="notification-popup-${
                        i.notification.id
                      }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
                      i.notification.id
                    }Label" aria-hidden="true">
                        <div class="modal-dialog" role="document">
      
                          <div class="modal-content">
                            <div class="modal-header">
                              <h5 class="modal-title" id="notification-popup-${
                                i.notification.id
                              }Label">${i.title}</h5>
                            </div>
                            <div class="modal-body">
                              <p class="text-center">${i.text}</p>
                              <video
                              gift-id="${i.notification.id}"
                              gifted-coins="${i.notification.gifted_coins}"
                              id="${
                                i.notification.is_gift && !i.notification.is_claimed
                                  ? `engage-gift-${i.notification.id}`
                                  : `engage-player`
                              }"
                              class="video-js"
                              preload="auto"
                              poster="/static/img/top-logo.png"
                              data-setup='{}'>
                                <source src="${
                                  i.notification.video
                                }" type="video/${i.notification.video
                      .split(/[#?]/)[0]
                      .split(".")
                      .pop()
                      .trim()}"></source>
                                <p class="vjs-no-js">
                                  To view this video please enable JavaScript, and consider upgrading to a
                                  web browser that
                                  <a href="https://videojs.com/html5-video-support/" target="_blank">
                                    supports HTML5 video
                                  </a>
                                </p>
                              </video>
                            </div>
                          </div>
      
                        </div>
                      </div>
                    `);
                  }
                }
    
                if (i.notification.action == "image") {
                  var image = (i.notification.translations[lang]==undefined)?i.notification.translations[defaultlang].image:i.notification.translations[lang].image;
                  if (
                    image &&
                    i.notification.is_gift &&
                    !i.notification.is_claimed
                  ) {
                    $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">
      
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text}</p>
                          <a
                          id="${i.notification.id}"
                          gifted_coins="${i.notification.gifted_coins}"
                          class="claim-gift"
                        >
                          <img
                          class="notification-img"
                            src="${image}"
                          />
                        </a>
                        </div>
                      </div>
      
                    </div>
                  </div>
                `);
                  } else if (image) {
                    var index=0;var tournament_name="";var prize_name="";var prize_image="";
                    if(i.link!=null && i.link.indexOf(';')>0){
                      tournament_name=i.link.split(';')[0].replace('"','');
                      prize_name=i.link.split(';')[1];
                      prize_image='/media/'+i.link.split(';')[2];
                    }
                  
                    if(i.notification.template == 'user_first_tournament'){
                    index=1;
                    }
                    else if(i.notification.template == 'user_second_third_tournament'){
                    index=2;
                    }
                    else if(i.notification.template=='user_outside_the_winning_positions'){
                      index=3;
                    }
                    else if(i.notification.template=='complete_profile'){
                      index=4;
                    }
                    $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">
      
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text} </p>
                          <img
                          class="notification-img" onclick="openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
                            src="${image}" />
                        </div>
                      </div>
      
                    </div>
                  </div>
                `);
                  } else {
                    $("#notifications-popup").append(`
                  <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
                    <div class="modal-dialog" role="document">
      
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
                        </div>
                        <div class="modal-body">
                          <p class="text-center">${i.text}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                `);
                  }
                }
              });
            }
            if(allread.length==0) {
              $('#notifications-count').css('background','#800080');
            }
              





      
      // getNewNotifications().then(function (result) {
      //   // set notifications badge >> count
      //   $("#notifications-count").text(`${result.length}`);

      //   if (result.length >= 1) {
      //     $('#notifications-count').css('background','#EA2D2D');
      //     // re-append the notifications
      //     $("#notification-list").append(`
      //       <li class="header-noti">
      //           <h5>New</h5>
      //       </li>
      //   `);

      //     result.map((i) => {
      //       if (i.notification.action == "text" && i.friend_uid == undefined && i.notification.template=='user_register_for_tournament') {
      //         $("#notification-list").append(`
      //         <li class="new-notification">
      //             <a
      //               id="${i.notification.id}"
      //               data-id="${i.id}"
      //               url="${i.link}"
      //               action="${i.notification.action}"
      //               class="notification"
      //             >
      //                 <span class="title">${i.title}</span>
      //                 <span class="desc">${i.text}</span>
      //                 <span class="date">${moment(i.created).format(
      //                   "MMMM DD YYYY, h:mm:ss a"
      //                 )}</span>
      //             </a>
      //         </li>
      //     `);
      //       } 
      //       else if (i.notification.action == "text" && i.friend_uid == undefined && (i.notification.template=='before_match_informative' || i.notification.template=='win_match_informative')) {
      //         $("#notification-list").append(`
      //         <li class="new-notification">
      //             <a
      //               id="${i.notification.id}"
      //               data-id="${i.id}"
      //               url="${i.link}"
      //               action="${i.notification.action}"
      //               class="notification"
      //             >
      //                 <span class="title">${i.title}</span>
      //                 <span class="desc">${i.text}</span>
      //                 <span class="date">${moment(i.created).format(
      //                   "MMMM DD YYYY, h:mm:ss a"
      //                 )}</span>
      //             </a>
      //         </li>
      //     `);
      //       } 
      //       else if (i.notification.action == "text" && i.friend_uid == undefined) {
      //         /////////////////////////////////////////////////////////
      //         if(i.notification.template == "complete_profile")
      //         {
      //             var profileUrl = $('.nav-my-profile').attr('href');
      //             $("#notification-list").append(`
      //             <li class="new-notification">
      //                 <a
      //                   id="${i.notification.id}"
      //                   data-id="${i.id}"
      //                   url="${i.notification.url}"
      //                   action="${i.notification.action}"
      //                   onclick="openEditProfileModal(event)"                      
      //                   class="notification"
      //                 >
      //                     <span class="title">${i.title}</span>  
      //                     <span class="desc">${i.text}</span>
      //                     <span class="date">${moment(i.created).format(
      //                       "MMMM DD YYYY, h:mm:ss a"
      //                     )}</span>
      //                 </a>
      //             </li>
      //         `);            
      //         }else{
      //           console.log("here ");

      //           if(i.notification.url && i.notification.url.indexOf('#home-tournaments') != -1)
      //           {
      //             console.log("here 1");
      //         $("#notification-list").append(`
      //         <li class="new-notification">
      //             <a
      //               id="${i.notification.id}"
      //               data-id="${i.id}"
      //               url="${i.notification.url}"
      //               action="${i.notification.action}"
      //               class="notification" onclick="$('.tab-link.tour-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);"
      //             >
      //                 <span class="title">${i.title}</span>
      //                 <span class="desc">${i.text}</span>
      //                 <span class="date">${moment(i.created).format(
      //                   "MMMM DD YYYY, h:mm:ss a"
      //                 )}</span>
      //             </a>
      //         </li>
      //     `);
      //                 }
      //                 else if(i.notification.url && i.notification.url.indexOf('#home-games') != -1)
      //                 {
                         
      //               $("#notification-list").append(`
      //               <li class="new-notification">
      //                   <a
      //                     id="${i.notification.id}"
      //                     data-id="${i.id}"
      //                     url="${i.notification.url}"
      //                     action="${i.notification.action}"
      //                     class="notification" onclick="$('.games-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);"
      //             >
      //                 <span class="title">${i.title}</span>
      //                 <span class="desc">${i.text}</span>
      //                 <span class="date">${moment(i.created).format(
      //                   "MMMM DD YYYY, h:mm:ss a"
      //                 )}</span>
      //             </a>
      //         </li>
      //     `);
      //                 }
      //                 else{
      //         $("#notification-list").append(`
      //         <li class="new-notification">
      //             <a
      //               id="${i.notification.id}"
      //               data-id="${i.id}"
      //               url="${i.notification.url}"
      //               action="${i.notification.action}"
      //               class="notification"
      //             >
      //                 <span class="title">${i.title}</span>
      //                 <span class="desc">${i.text}</span>
      //                 <span class="date">${moment(i.created).format(
      //                   "MMMM DD YYYY, h:mm:ss a"
      //                 )}</span>
      //             </a>
      //         </li>
      //     `);

      //                 }

                
      //         }

      //       } 
      //       else {
      //         var friend_request = i.friend_uid
      //           ? `
      //       <div class="col-md-12">
      //       <div id="accept-new-friend" target="${i.friend_uid}" class="btn2 big" >Accept</div>
      //       <button id="reject-new-friend" target="${i.friend_uid}" class="btn2 big" >Reject</button>
      //       </div>
      //       `
      //           : "";

      //         $("#notification-list").append(`
      //         <li class="new-notification">
      //             <p 
      //               id="${i.notification.id}"
      //               data-id="${i.id}"
      //               action="${i.notification.action}"
      //               class="notification"
      //             >
      //                 <span class="title">${i.title}</span>
      //                 <span class="desc">${i.text}</span>

      //                 ${friend_request}

      //                 <span class="date">${moment(i.created).format(
      //                   "MMMM DD YYYY, h:mm:ss a"
      //                 )}</span>
      //             </p>
      //         </li>
      //     `);
      //       }

      //       if (i.notification.action == "video") {
      //         if (i.notification.video) {
      //           $("#notifications-popup").append(`
      //             <div class="modal fade" id="notification-popup-${
      //               i.notification.id
      //             }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
      //             i.notification.id
      //           }Label" aria-hidden="true">
      //               <div class="modal-dialog" role="document">
  
      //                 <div class="modal-content">
      //                   <div class="modal-header">
      //                     <h5 class="modal-title" id="notification-popup-${
      //                       i.notification.id
      //                     }Label">${i.title}</h5>
      //                   </div>
      //                   <div class="modal-body">
      //                     <p class="text-center">${i.text}</p>
      //                     <video
      //                     gift-id="${i.notification.id}"
      //                     gifted-coins="${i.notification.gifted_coins}"
      //                     id="${
      //                       i.notification.is_gift && !i.notification.is_claimed
      //                         ? `engage-gift-${i.notification.id}`
      //                         : `engage-player`
      //                     }"
      //                     class="video-js"
      //                     preload="auto"
      //                     poster="/static/img/top-logo.png"
      //                     data-setup='{}'>
      //                       <source src="${
      //                         i.notification.video
      //                       }" type="video/${i.notification.video
      //             .split(/[#?]/)[0]
      //             .split(".")
      //             .pop()
      //             .trim()}"></source>
      //                       <p class="vjs-no-js">
      //                         To view this video please enable JavaScript, and consider upgrading to a
      //                         web browser that
      //                         <a href="https://videojs.com/html5-video-support/" target="_blank">
      //                           supports HTML5 video
      //                         </a>
      //                       </p>
      //                     </video>
      //                   </div>
      //                 </div>
  
      //               </div>
      //             </div>
      //           `);
      //         }
      //       }

      //       if (i.notification.action == "image") {
      //         var image = (i.notification.translations[lang]==undefined)?i.notification.translations[defaultlang].image:i.notification.translations[lang].image;
      //         if (
      //           image &&
      //           i.notification.is_gift &&
      //           !i.notification.is_claimed
      //         ) {
      //           $("#notifications-popup").append(`
      //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
      //           <div class="modal-dialog" role="document">
  
      //             <div class="modal-content">
      //               <div class="modal-header">
      //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
      //               </div>
      //               <div class="modal-body">
      //                 <p class="text-center">${i.text}</p>
      //                 <a
      //                 id="${i.notification.id}"
      //                 gifted_coins="${i.notification.gifted_coins}"
      //                 class="claim-gift"
      //               >
      //                 <img
      //                 class="notification-img"
      //                   src="${image}"
      //                 />
      //               </a>
      //               </div>
      //             </div>
  
      //           </div>
      //         </div>
      //       `);
      //         } else if (image) {
      //           var index=0;var tournament_name="";var prize_name="";var prize_image="";
      //           if(i.link!=null && i.link.indexOf(';')>0){
      //             tournament_name=i.link.split(';')[0].replace('"','');
      //             prize_name=i.link.split(';')[1];
      //             prize_image='/media/'+i.link.split(';')[2];
      //           }
              
      //           if(i.notification.template == 'user_first_tournament'){
      //           index=1;
      //           }
      //           else if(i.notification.template == 'user_second_third_tournament'){
      //           index=2;
      //           }
      //           else if(i.notification.template=='user_outside_the_winning_positions'){
      //             index=3;
      //           }
      //           else if(i.notification.template=='complete_profile'){
      //             index=4;
      //           }
      //           $("#notifications-popup").append(`
      //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
      //           <div class="modal-dialog" role="document">
  
      //             <div class="modal-content">
      //               <div class="modal-header">
      //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
      //               </div>
      //               <div class="modal-body">
      //                 <p class="text-center">${i.text} </p>
      //                 <img
      //                 class="notification-img" onclick="openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
      //                   src="${image}" />
      //               </div>
      //             </div>
  
      //           </div>
      //         </div>
      //       `);
      //         } else {
      //           $("#notifications-popup").append(`
      //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
      //           <div class="modal-dialog" role="document">
  
      //             <div class="modal-content">
      //               <div class="modal-header">
      //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
      //               </div>
      //               <div class="modal-body">
      //                 <p class="text-center">${i.text}</p>
      //               </div>
      //             </div>
      //           </div>
      //         </div>
      //       `);
      //         }
      //       }
      //     });
      //   }
      //   else{
      //     $('#notifications-count').css('background','#650f5e');
      //   }

        // getEarlyNotifications().then(function (result) {
        //   if (result.pagination.has_next) {
        //     early_notifications_has_next = true;
        //     current_early_notifications_page = 2;
        //   } else {
        //     early_notifications_has_next = false;
        //   }

        //   if (result.data.length >= 1) {
        //     $("#notification-list").append(`
        //     <li class="header-noti">
        //         <h5>Earlier</h5>
        //     </li>
        //   `);

        //     result.data.map((i) => {
        //       if (
        //         i.notification.action == "text" &&
        //         i.friend_uid == undefined && i.notification.template=='user_register_for_tournament'
        //       ) {
        //         $("#notification-list").append(`
        //         <li class="earlier-notification 5">
        //             <a id="${i.notification.id}"  url="${
        //           i.link
        //         }"  data-id="${i.id}" action="${i.notification.action}" class="notification">
        //                 <span class="title">${i.title}</span>
        //                 <span class="desc">${i.text}</span>
        //                 <span class="date">${moment(i.created).format(
        //                   "MMMM DD YYYY, h:mm:ss a"
        //                 )}</span>
        //             </a>
        //         </li>
        //     `);
        //       } 
        //       else if (
        //         i.notification.action == "text" &&
        //         i.friend_uid == undefined && (i.notification.template=='before_match_informative' || i.notification.template=='win_match_informative')
        //       ) {
        //         $("#notification-list").append(`
        //         <li class="earlier-notification 6">
        //             <a id="${i.notification.id}"  url="${
        //           i.link
        //         }"  data-id="${i.id}" action="${i.notification.action}" class="notification">
        //                 <span class="title">${i.title}</span>
        //                 <span class="desc">${i.text}</span>
        //                 <span class="date">${moment(i.created).format(
        //                   "MMMM DD YYYY, h:mm:ss a"
        //                 )}</span>
        //             </a>
        //         </li>
        //     `);
        //       } 
        //       else if (
        //         i.notification.action == "text" &&
        //         i.friend_uid == undefined 
        //       ) {
        //             if(i.title == "Complete profile and get rewarded")
        //             {
        //               $("#notification-list").append(`
        //         <li class="earlier-notification 7">
        //             <a id="${i.notification.id}"  url="${
        //           i.notification.url
        //         }"  data-id="${i.id}" action="${i.notification.action}" class="notification" href="#settings-modal" onclick="openEditProfileModal(event)">
        //                 <span class="title">${i.title}</span>
        //                 <span class="desc">${i.text}</span>
        //                 <span class="date">${moment(i.created).format(
        //                   "MMMM DD YYYY, h:mm:ss a"
        //                 )}</span>
        //             </a>
        //         </li>
        //     `);                     
        //             }
        //             else{

        //               if(i.notification.url && i.notification.url.indexOf('#home-tournaments') != -1)
        //               { 
        //         $("#notification-list").append(`
        //         <li class="earlier-notification 8">
        //             <a id="${i.notification.id}"  url="${
        //           i.notification.url
        //         }"  data-id="${i.id}" action="${i.notification.action}" class="notification" onclick="$('.tab-link.tour-btn').click();$('html, body').animate({ scrollTop: $('#tournaments').offset().top }, 1000);">
        //                 <span class="title">${i.title}</span>
        //                 <span class="desc">${i.text}</span>
        //                 <span class="date">${moment(i.created).format(
        //                   "MMMM DD YYYY, h:mm:ss a"
        //                 )}</span>
        //             </a>
        //         </li>
        //     `);                     
        //             }
        //             else{
        //         $("#notification-list").append(`
        //         <li class="earlier-notification">
        //             <a id="${i.notification.id}"  url="${
        //           i.notification.url
        //         }"  data-id="${i.id}" action="${i.notification.action}" class="notification">
        //                 <span class="title">${i.title}</span>
        //                 <span class="desc">${i.text}</span>
        //                 <span class="date">${moment(i.created).format(
        //                   "MMMM DD YYYY, h:mm:ss a"
        //                 )}</span>
        //             </a>
        //         </li>
        //     `);

        //                 }


        //             }
        //       } else {
        //         var friend_request = i.friend_uid
        //           ? `
        //       <div class="col-md-12">
        //       <div id="accept-new-friend" target="${i.friend_uid}" class="btn2 big" >Accept</div>
        //       <button id="reject-new-friend" target="${i.friend_uid}" class="btn2 big" >Reject</button>
        //       </div>
        //       `
        //           : "";

        //         $("#notification-list").append(`
        //         <li class="earlier-notification 9">
        //             <p id="${i.notification.id}" action="${
        //           i.notification.action
        //         }" class="notification">
        //                 <span class="title">${i.title}</span>
        //                 <span class="desc">${i.text}</span>
  
        //                 ${friend_request}
  
        //                 <span class="date">${moment(i.created).format(
        //                   "MMMM DD YYYY, h:mm:ss a"
        //                 )}</span>
        //             </p>
        //         </li>
        //     `);
        //       }

        //       if (i.notification.action == "video") {
        //         if (i.notification.video) {
        //           $("#notifications-popup").append(`
        //             <div class="modal fade" id="notification-popup-${
        //               i.notification.id
        //             }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
        //             i.notification.id
        //           }Label" aria-hidden="true">
        //               <div class="modal-dialog" role="document">
    
        //                 <div class="modal-content">
        //                   <div class="modal-header">
        //                     <h5 class="modal-title" id="notification-popup-${
        //                       i.notification.id
        //                     }Label">${i.title}</h5>
        //                   </div>
        //                   <div class="modal-body">
        //                     <p class="text-center">${i.text}</p>
        //                     <video
        //                     gift-id="${i.notification.id}"
        //                     gifted-coins="${i.notification.gifted_coins}"
        //                     id="${
        //                       i.notification.is_gift &&
        //                       !i.notification.is_claimed
        //                         ? `engage-gift-${i.notification.id}`
        //                         : `engage-player`
        //                     }"
        //                     class="video-js"
        //                     preload="auto"
        //                     poster="/static/img/top-logo.png"
        //                     data-setup='{}'>
        //                       <source src="${
        //                         i.notification.video
        //                       }" type="video/${i.notification.video
        //             .split(/[#?]/)[0]
        //             .split(".")
        //             .pop()
        //             .trim()}"></source>
        //                       <p class="vjs-no-js">
        //                         To view this video please enable JavaScript, and consider upgrading to a
        //                         web browser that
        //                         <a href="https://videojs.com/html5-video-support/" target="_blank">
        //                           supports HTML5 video
        //                         </a>
        //                       </p>
        //                     </video>
        //                   </div>
        //                 </div>
    
        //               </div>
        //             </div>
        //           `);
        //         }
        //       }

        //       if (i.notification.action == "image") {
        //         var image = (i.notification.translations[lang]==undefined)?i.notification.translations[defaultlang].image:i.notification.translations[lang].image;
        //         if (
        //           image &&
        //           i.notification.is_gift &&
        //           !i.notification.is_claimed
        //         ) {
        //           $("#notifications-popup").append(`
        //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
        //           <div class="modal-dialog" role="document">
    
        //             <div class="modal-content">
        //               <div class="modal-header">
        //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
        //               </div>
        //               <div class="modal-body">
        //                 <p class="text-center">${i.text} </p>
        //                 <a
        //                 id="${i.notification.id}"
        //                 gifted_coins="${i.notification.gifted_coins}"
        //                 class="claim-gift"
        //                 >
        //                   <img
        //                   class="notification-img"
        //                     src="${image}"
        //                   />
        //                 </a>
        //               </div>
        //             </div>
    
        //           </div>
        //         </div>
        //       `);
        //         } else if (image) {
        //           var index=0;var tournament_name="";var prize_name="";var prize_image="";
        //           if(i.link!=null && i.link.indexOf(';')>0){
        //             tournament_name=i.link.split(';')[0].replace('"','');
        //             prize_name=i.link.split(';')[1];
        //             prize_image='/media/'+i.link.split(';')[2];
        //           }
                
        //           if(i.notification.template == 'user_first_tournament'){
        //           index=1;
        //           }
        //           else if(i.notification.template == 'user_second_third_tournament'){
        //           index=2;
        //           }
        //           else if(i.notification.template=='user_outside_the_winning_positions'){
        //             index=3;
        //           }
        //           else if(i.notification.template=='complete_profile'){
        //             index=4;
        //           }
        //           $("#notifications-popup").append(`
        //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
        //           <div class="modal-dialog" role="document">
    
        //             <div class="modal-content">
        //               <div class="modal-header">
        //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
        //               </div>
        //               <div class="modal-body">
        //                 <p class="text-center">${i.text}  </p>
        //                 <img
        //                   class='notification-img' onclick="openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
        //                   src="${image}" />
        //               </div>
        //             </div>
        //           </div>
        //         </div>
        //       `);
        //         } else {
        //           $("#notifications-popup").append(`
        //         <div class="modal fade" id="notification-popup-${i.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${i.notification.id}Label" aria-hidden="true">
        //           <div class="modal-dialog" role="document">
    
        //             <div class="modal-content">
        //               <div class="modal-header">
        //                 <h5 class="modal-title" id="notification-popup-${i.notification.id}Label">${i.title}</h5>
        //               </div>
        //               <div class="modal-body">
        //                 <p class="text-center">${i.text}</p>
        //               </div>
        //             </div>
    
        //           </div>
        //         </div>
        //       `);
        //         }
        //       }
        //     });
        //   }

          loading = false;
 
          //
          if(isIphone){ 
            $("body").delegate("#accept-new-friend", "click touchstart", function (e) {
             var target = $(this).attr("target");
             
             setBtnLoading($(e.target), true);
         
             $.ajax({
               url: friends_list_accept,
               headers: {
                 "X-CSRFToken": csrftoken,
               },
               type: "post",
               data: {
                 friend: target,
               },
               error: function (value) {
                 setBtnLoading($(e.target), false);
                 console.log("Error:", value.statusText);
               },
               success: function (value) {
                 getNewNotifications()
                   .then(function (result) {
                     // set notifications badge >> count
                     $("#notifications-count").text(`${result.length}`);
                      if(result.length > 0)
                        $('#notifications-count').css('background','#EA2D2D');
                      else
                        $('#notifications-count').css('background','#650f5e');
                     // reset the notifications list
                     $("#notification-list").empty();
         
                     // re-append the notifications
                     $("#notification-list").append(`
                     <div class="d-flex flex-row justify-content-center align-items-center align-content-center" style="height: 200px;">
                       <div class="align-self-center spinner-grow text-dark" role="status"></div>
                     </div>
                   `);
         
                     // remove notifications models
                     $("#notifications-popup").empty();
         
                     getAllNotifications();
                   })
                   .catch(function (error) {
                     console.log("error", error);
                   });
         
                 setBtnLoading($(e.target), false);
                 $(".notification-dropdown").removeClass("show-notification");
                 if(location.href.toLowerCase().indexOf('#friends')>=0){
                   location.reload();
                 }
               },
             });
           });
         
           $("body").delegate("#reject-new-friend", "click touchstart", function (e) {
             var target = $(this).attr("target");
         
             setBtnLoading($(e.target), true);
         
             $.ajax({
               url: friends_list_reject,
               headers: {
                 "X-CSRFToken": csrftoken,
               },
               type: "post",
               data: {
                 friend: target,
               },
               error: function (value) {
                 setBtnLoading($(e.target), false);
                 console.log("Error:", value.statusText);
               },
               success: function (value) {
                 getNewNotifications()
                   .then(function (result) {
                     // set notifications badge >> count
                     $("#notifications-count").text(`${result.length}`);
                     if(result.length > 0)
                      $('#notifications-count').css('background','#EA2D2D');
                      else
                      $('#notifications-count').css('background','#650f5e');
                     // reset the notifications list
                     $("#notification-list").empty();
         
                     // re-append the notifications
                     $("#notification-list").append(`
                     <div class="d-flex flex-row justify-content-center align-items-center align-content-center" style="height: 200px;">
                       <div class="align-self-center spinner-grow text-dark" role="status"></div>
                     </div>
                   `);
         
                     // remove notifications models
                     $("#notifications-popup").empty();
         
                     getAllNotifications();
                   })
                   .catch(function (error) {
                     console.log("error", error);
                   });
         
                 setBtnLoading($(e.target), false);
                 $(".notification-dropdown").removeClass("show-notification");
               },
             });
           });
          }
         

          //
          
        });
       
  //    });
      
    }

     
  }; 

  // on notification button clicked
  $(".notification-btn").click(function () {
    getAllNotifications();
    //getNewEarlyNotifications();
  });

  document.addEventListener('visibilitychange', function (event) {
    if (document.hidden) {
        console.log('not visible');
    } else {
        console.log('is visible');
        is_active = true;
    }
});

  $(document).ready(function(){
    
    //loadUnreadPopups();

    $(window).focus(function () {
      //console.log("in focus")
      clearInterval(myInterval); // Clearing interval if for some reason it has not been cleared yet

      loadUnreadPopups();
      getAllNotifications();
      
      if  (!is_interval_running && is_active) //Optional
          myInterval = setInterval(myTimer, interval_delay);
      
  }).blur(function () {
    console.log("not in focus")
    clearInterval(myInterval); // Clearing interval on window blur
    is_interval_running = false; //Optional
});
  
});

function myTimer() {
  is_interval_running = true; 

  loadUnreadPopups();
  getAllNotifications();
  
};


  // on claim click
  $("body").delegate(".claim-gift", "click", function () {
    var notification_id = $(this).attr("id");
    var gifted_coins = $(this).attr("gifted_coins");

    $.ajax({
      url: claim_gift_url,
      headers: {
        "X-CSRFToken": csrftoken,
      },
      type: "post",
      data: {
        id: notification_id,
      },
      error: function (value) {
        $(`#notification-popup-${notification_id}`).modal("toggle");
      },
      success: function (value) {
        if (value && value.status == "success") {
          var user_coins = parseInt($("#actual-user-coins").text());
          $("#actual-user-coins, .user-coins").text(value.coins);
          if(parseInt(gifted_coins) > 0){
            $('#user-coins').css('background','#EA2D2D');
          }
          // $("#actual-user-coins, .user-coins").text(
          //   `${
          //     user_coins > 0
          //       ? user_coins + parseInt(gifted_coins)
          //       : gifted_coins
          //   }`
          // );
        }

        $(`#notification-popup-${notification_id}`).modal("toggle");
        $(this).removeClass('new-notification').addClass('earlier-notification');
      },
    });
  });

  Notification.requestPermission().then((permission) => {
    if (permission === "granted") {
      messaging
        .getToken({
          vapidKey:
            //"BJfaeey4LJqGRybfY7shu20U-cKY8W2ywEPxCw1Lo3RRP6dr-meRlg74-qL5eswNln8aEn-P-x37P56GMDjVXZQ",
            "BIupobxzHwPR8eaxnVfRKKZhFAMTS6PQr0QIRC7lKSasYKFCIXVO8XSgXP4BMt9Z9xPDU-zxdWqXLODK2mZyHJc",
        })
        .then((currentToken) => {
          if (currentToken) {
            // send the fcm token to backend
            $.ajax({
              url: fcm_web_token_url,
              headers: {
                "X-CSRFToken": csrftoken,
              },
              type: "post",
              data: {
                fcm_token: currentToken,
              },
              error: function (value) {
                console.log("Error:", value.statusText);
              },
              success: function (value) {},
            });
          } else {
            console.log(
              "No registration token available. Request permission to generate one."
            );
          }
        })
        .catch((err) => {
          console.log("An error occurred while retrieving token. ", err);
        });
    }
  });

  $("body").delegate(".video-js", "click", function () {
    var notification_id = $(this).attr("gift-id");

    videojs(this).ready(function () {
      if (!this.controls_) {
        var gifted_coins = $(this).attr("gifted-coins");

        this.controls(true);
        this.play();

        setTimeout(function () {
          $.ajax({
            url: claim_gift_url,
            headers: {
              "X-CSRFToken": csrftoken,
            },
            type: "post",
            data: {
              id: notification_id,
            },
            error: function (value) {},
            success: function (value) {
              if (value && value.status == "success") {
                var user_coins = parseInt($("#actual-user-coins").text());
                if(parseInt(gifted_coins) > 0){
                  $('#user-coins').css('background','#EA2D2D');
                }
                $(".user-coins").text(
                  `${
                    user_coins > 0
                      ? user_coins + parseInt(gifted_coins)
                      : gifted_coins
                  }`
                );
              }
            },
          });
        }, 1000);
      }
    });
  });
  



  $("body").delegate("#accept-new-friend", "click touchstart", function (e) {
   var target = $(this).attr("target");
   
    setBtnLoading($(e.target), true);

    $.ajax({
      url: friends_list_accept,
      headers: {
        "X-CSRFToken": csrftoken,
      },
      type: "post",
      data: {
        friend: target,
      },
      error: function (value) {
        setBtnLoading($(e.target), false);
        console.log("Error:", value.statusText);
      },
      success: function (value) {
        getNewNotifications()
          .then(function (result) {
            // set notifications badge >> count
            $("#notifications-count").text(`${result.length}`);
            if(result.length > 0)
              $('#notifications-count').css('background','#EA2D2D');
            else
              $('#notifications-count').css('background','#650f5e');
            // reset the notifications list
            $("#notification-list").empty();

            // re-append the notifications
            $("#notification-list").append(`
            <div class="d-flex flex-row justify-content-center align-items-center align-content-center" style="height: 200px;">
              <div class="align-self-center spinner-grow text-dark" role="status"></div>
            </div>
          `);

            // remove notifications models
            $("#notifications-popup").empty();

            getAllNotifications();
          })
          .catch(function (error) {
            console.log("error", error);
          });

        setBtnLoading($(e.target), false);
        $(".notification-dropdown").removeClass("show-notification");
        if(location.href.toLowerCase().indexOf('#friends')>=0){
          location.reload();
        }
      },
    });
  });

  $("body").delegate("#reject-new-friend", "click touchstart", function (e) {
    var target = $(this).attr("target");

    setBtnLoading($(e.target), true);

    $.ajax({
      url: friends_list_reject,
      headers: {
        "X-CSRFToken": csrftoken,
      },
      type: "post",
      data: {
        friend: target,
      },
      error: function (value) {
        setBtnLoading($(e.target), false);
        console.log("Error:", value.statusText);
      },
      success: function (value) {
        getNewNotifications()
          .then(function (result) {
            // set notifications badge >> count
            $("#notifications-count").text(`${result.length}`);
            if(result.length > 0)
            $('#notifications-count').css('background','#EA2D2D');
            else
            $('#notifications-count').css('background','#650f5e');
            // reset the notifications list
            $("#notification-list").empty();

            // re-append the notifications
            $("#notification-list").append(`
            <div class="d-flex flex-row justify-content-center align-items-center align-content-center" style="height: 200px;">
              <div class="align-self-center spinner-grow text-dark" role="status"></div>
            </div>
          `);

            // remove notifications models
            $("#notifications-popup").empty();

            getAllNotifications();
          })
          .catch(function (error) {
            console.log("error", error);
          });

        setBtnLoading($(e.target), false);
        $(".notification-dropdown").removeClass("show-notification");
      },
    });
  });
 
 
  firebaseApp.messaging().getToken().then((currentToken) => {
    if (currentToken) {
      console.log(currentToken)
    } else {
      // Show permission request.
      console.log(
        'No Instance ID token available. Request permission to generate one.')
    }

  messaging.onMessage(async function (payload) {
    console.log('Message received. ', payload);
    var notification = payload.data;
    
    // navigator.serviceWorker.ready
    //   .then((registration) => {
    //     registration.showNotification(notification.title, {
    //       body: notification.body,
    //       icon: "/static/img/notification-icon.png",
    //     });
    //   })
    //   .catch((error) => {
    //     console.log(error);
    //   });

    $.ajax({
      url: get_user_notifications_url,
      headers: {
        "X-CSRFToken": csrftoken,
      },
      type: "get",
      data: {
        title:payload.data.title,
        body:payload.data.body
      },
      error: function (value) {
     
      },
      success: function (value) {
        console.log('value',value);
       if((value.subscription=='free' &&  value.package_ids.indexOf(1)) || (value.subscription=='paid1' &&  value.package_ids.indexOf(2)) || (value.subscription=='paid2' &&  value.package_ids.indexOf(3)) ){
          navigator.serviceWorker.ready
          .then((registration) => {
            registration.showNotification(value.data.title, {
              body: value.data.text,
              icon: "/static/img/notification-icon.png",
            });
          })
          .catch((error) => {
            console.log(error);
          });
        }

       if(value.data.is_popup==true && value.data.notification.action == "video"){
          $("#notifications-popup").append(`
          <div class="modal fade" id="notification-popup-${
            value.data.notification.id
          }" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${
            value.data.notification.id
        }Label" aria-hidden="true">
            <div class="modal-dialog" role="document">

              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="notification-popup-${
                    value.data.notification.id
                  }Label">${value.data.title}</h5>
                </div>
                <div class="modal-body">
                  <p class="text-center">${value.data.text}</p>
                  <video
                  gift-id="${value.data.notification.id}"
                  gifted-coins="${value.data.notification.gifted_coins}"
                  id="${
                    value.data.notification.is_gift && !value.data.is_claimed
                      ? `engage-gift-${value.data.notification.id}`
                      : `engage-player`
                  }"
                  class="video-js"
                  preload="auto"
                  poster="/static/img/top-logo.png"
                  data-setup='{}'>
                  <source src="${
                    value.data.notification.video
                  }" type="video/${value.data.notification.video
                .split(/[#?]/)[0]
                .split(".")
                .pop()
                .trim()}"></source>
                    <p class="vjs-no-js">
                      To view this video please enable JavaScript, and consider upgrading to a
                      web browser that
                      <a href="https://videojs.com/html5-video-support/" target="_blank">
                        supports HTML5 video
                      </a>
                    </p>
                  </video>
                </div>
              </div>

            </div>
          </div>
          `);
          setTimeout(function(){ 
             $("#notifications-popup").find("#notification-popup-"+value.data.notification.id).modal({
            show: true,
            keyboard: true,
            backdrop: true,
          });
          $("#notifications-popup").find("#notification-popup-"+value.data.notification.id).on('hidden.bs.modal', function () {
            updateNotificationStatus(value.data.id);
          })
        },1000)
        
          $('#notification-popup-'+value.data.notification.id).each(function(){
            if($(this).parents().hasClass('modal-open'))
            $(this).removeClass('show').hide();
          })
       }
       else if(value.data.is_popup==true && value.data.notification.action == "image"){
        if (
          value.data.notification.translations['en-us'].image &&
          value.data.notification.is_gift &&
          !value.data.notification.is_claimed
        ) {
          
          $("#notifications-popup").append(`
        <div class="modal fade" id="notification-popup-${value.data.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${value.data.notification.id}Label" aria-hidden="true">
          <div class="modal-dialog" role="document">

            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title" id="notification-popup-${value.data.notification.id}Label">${value.data.title}</h5>
              </div>
              <div class="modal-body">
                <p class="text-center">${value.data.text}   </p>
                <a
                id="${value.data.notification.id}"
                gifted_coins="${value.data.notification.gifted_coins}"
                class="claim-gift"
                >
                  <img
                    class="notification-img"
                    src="${value.data.notification.image}"
                  />
                </a>
              </div>
            </div>

          </div>
        </div>
        `);
        } 
         else if (value.data.notification.image) {
          var index=0;var tournament_name="";var prize_name="";var prize_image="";
          if(value.data.link!=null && value.data.link.indexOf(';')>0){
            tournament_name=value.data.link.split(';')[0].replace('"','');
            prize_name=value.data.link.split(';')[1];
            prize_image='/media/'+value.data.link.split(';')[2];
          }
        
          if(value.data.notification.template == 'user_first_tournament'){
          index=1;
          }
          else if(value.data.notification.template == 'user_second_third_tournament'){
          index=2;
          }
          else if(value.data.notification.template=='user_outside_the_winning_positions'){
            index=3;
          }
          else if(i.notification.template=='complete_profile'){
            index=4;
          }
          $("#notifications-popup").append(`
        <div class="modal fade" id="notification-popup-${value.data.notification.id}" tabindex="-1" role="dialog" aria-labelledby="notification-popup-${value.data.notification.id}Label" aria-hidden="true">
          <div class="modal-dialog" role="document">

            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title" id="notification-popup-${value.data.notification.id}Label">${value.data.title}</h5>
              </div>
              <div class="modal-body">
                <p class="text-center">${value.data.text} </p>
                <img
                class="notification-img" onclick="$(this).parents('.modal').removeClass('show').hide();openModal(`+index+`,'`+tournament_name+`','`+prize_name+`','`+prize_image+`')"
                  src="${value.data.notification.image}" />
              </div>
            </div>
          </div>
        </div>
      `);
         }

         $("#notifications-popup").find("#notification-popup-"+value.data.notification.id).modal({
            show: true,
            keyboard: true,
            backdrop: true,
          });
          $("#notifications-popup").find("#notification-popup-"+value.data.notification.id).on('hidden.bs.modal', function () {
            updateNotificationStatus(value.data.id);
            $('body').removeClass('modal-open');
          })
          
       }
       
      },
    });


    getMyCoins()
      .then(function (result) {
        $("#actual-user-coins, .user-coins").text(`${result.data.coins}`);
      })
      .catch(function (error) {});

    getNewNotifications()
      .then(function (result) {
        // set notifications badge >> count
        $("#notifications-count").text(`${result.length}`);
        if(result.length > 0)
              $('#notifications-count').css('background','#EA2D2D');
        else
              $('#notifications-count').css('background','#650f5e');
        // reset the notifications list
        $("#notification-list").empty();

        // re-append the notifications
        $("#notification-list").append(`
          <div class="d-flex flex-row justify-content-center align-items-center align-content-center" style="height: 200px;">
            <div class="align-self-center spinner-grow text-dark" role="status"></div>
          </div>
        `);

        // remove notifications models
        $("#notifications-popup").empty();

        getAllNotifications();
      })
      .catch(function (error) {
        console.log("error", error);
      });

  getAllNotifications();})
  });

  
  // messaging.onBackgroundMessage(async function(payload) {
  //   console.log('[firebase-messaging-sw.js] Received background message ', payload);
  //   $.ajax({
  //     url: get_user_notifications_url,
  //     headers: {
  //       "X-CSRFToken": csrftoken,
  //     },
  //     type: "get",
  //     data: {
  //       title:payload.title,
  //       body:payload.body
  //     },
  //     error: function (value) {
       
  //     },
  //     success: function (value) {
  //       console.log('value',value);
  //       if((value.subscription=='free' &&  value.package_ids.indexOf(1)) || (value.subscription=='paid1' &&  value.package_ids.indexOf(2)) || (value.subscription=='paid2' &&  value.package_ids.indexOf(3)) ){
  //         navigator.serviceWorker.ready
  //         .then((registration) => {
  //           registration.showNotification(value.data.title, {
  //             body: value.data.text,
  //             icon: "/static/img/notification-icon.png",
  //           });
  //         })
  //         .catch((error) => {
  //           console.log(error);
  //         });
  //       }
      
  //     },
  //   });
    
   
  // })

  // messaging.onBackgroundMessage(async function(payload) {
  //   console.log('[firebase-messaging-sw.js] Received background message ', payload);
  //   // Customize notification here
  //   //const notificationTitle = 'Background Message Title';
  //   //const notificationOptions = {
  //   //  body: 'Background Message body.',
  //   //  icon: '/static/img/notification-icon.png'
  //   //};
  
  //   //self.registration.showNotification(notificationTitle,
  //   //  notificationOptions);
  //   getAllNotifications();
  // });
 
});

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "substrate.h"
#import <xpc/xpc.h>
#import <roothide.h>
#import <sandbox_private.h>
#import <ptrauth.h>
#import "../libSandy_private.h"

int64_t (*_xpc_interface_routine)(int msgid, xpc_object_t xmsg, xpc_object_t *xreply, uint64_t a4, uint64_t a5);

void consumeSandydGlobalExtensions(void)
{
	NSString *plistPath = jbroot(@"/usr/lib/sandyd_global.plist");
	if (!plistPath) return;
	NSDictionary *plistDict = [NSDictionary dictionaryWithContentsOfFile:plistPath];
	if (!plistDict) return;
	NSArray *extensions = plistDict[@"extensions"];
	if (!extensions) return;
	for (NSString *extension in extensions) {
		sandbox_extension_consume(extension.UTF8String);
	}
}

void (*__xpc_connection_set_event_handler)(xpc_connection_t connection, xpc_handler_t handler);
void _xpc_connection_set_event_handler(xpc_connection_t connection, xpc_handler_t handler)
{
	if (connection) {
		char *description = xpc_copy_description(connection);
		if (description) {
			if (strstr(description, " name = " SANDY_PROXY_IDENTIFER)) {
				xpc_handler_t newHandler = ^(xpc_object_t message) {
					if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {

						bool isSandyProxyMessage = xpc_dictionary_get_bool(message, "SandyProxy_Redirect");
						if (isSandyProxyMessage) {
							const char *nameToLookup = xpc_dictionary_get_string(message, "name");
							if (!strcmp(nameToLookup, "com.opa334.sandyd")) {
								consumeSandydGlobalExtensions();

								int msgid = xpc_dictionary_get_int64(message, "libsandy_msgid");
								NSLog(@"libsandy.dylib sent msgid %d", msgid);

								xpc_object_t messageToSend = xpc_dictionary_create(NULL, NULL, 0);
								xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t xobj) {
									if (!strcmp(key, "SandyProxy_Redirect")) return true;
									if (!strcmp(key, "libsandy_msgid")) return true;
									xpc_dictionary_set_value(messageToSend, key, xobj);
									return true;
								});

								xpc_object_t replyToSend = xpc_dictionary_create_reply(message);

								xpc_object_t reply;
								int r = _xpc_interface_routine(msgid, messageToSend, &reply, 1, 0);
								xpc_dictionary_set_int64(replyToSend, "SandyProxy_XPCRetCode", r);

								if (r == 0) {
									xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t xobj){
										xpc_dictionary_set_value(replyToSend, key, xobj);
										return true;
									});
								}
								xpc_connection_send_message(connection, replyToSend);
								return;
							}
						}
					}
					return handler(message);
				};

				__xpc_connection_set_event_handler(connection, newHandler);
				free(description);
				return;
			}
			free(description);
		}
	}

	__xpc_connection_set_event_handler(connection, handler);
}

/*
libhooker's MSFindSymbol doesn't sign function pointers at all, 
while rootless/ellekit's MSFindSymbol signs only all exported symbols(even data pointers). 
the new roothide/ellekit implements signing only all code pointers (whether exported or private).
this helper function is compatible with all of these.
*/
static void* FindAndSignFunction(MSImageRef image, const char *name)
{
	void* symbol = MSFindSymbol(image, name);
	if (!symbol) {
		return NULL;
	}
	return ptrauth_sign_unauthenticated(ptrauth_strip(symbol, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0);
}

%ctor
{
	if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_16_0) {
		MSImageRef xpcImage = MSGetImageByName("/usr/lib/system/libxpc.dylib");
		_xpc_interface_routine = FindAndSignFunction(xpcImage, "__xpc_interface_routine");
		MSHookFunction((void *)&xpc_connection_set_event_handler, (void *)_xpc_connection_set_event_handler, (void **)&__xpc_connection_set_event_handler);
	}
}
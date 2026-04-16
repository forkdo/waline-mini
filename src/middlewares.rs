use std::future::{Ready, ready};

use actix_web::{
  Error, HttpResponse,
  body::EitherBody,
  dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use futures_util::{FutureExt as _, TryFutureExt as _, future::LocalBoxFuture};

use url::Url;

use crate::helpers::header::{extract_origin, extract_referer};

#[derive(Clone, Debug)]
pub struct SecureDomains {
  secure_domains: Vec<String>,
}

impl SecureDomains {
  pub fn new(secure_domains: Vec<String>) -> Self {
    Self { secure_domains }
  }
}

impl<S, B> Transform<S, ServiceRequest> for SecureDomains
where
  S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
  S::Future: 'static,
  B: 'static,
{
  type Response = ServiceResponse<EitherBody<B>>;
  type Error = Error;
  type Transform = SecureDomainsService<S>;
  type InitError = ();
  type Future = Ready<Result<Self::Transform, Self::InitError>>;

  fn new_transform(&self, service: S) -> Self::Future {
    ready(Ok(SecureDomainsService {
      service,
      secure_domains: self.secure_domains.clone(),
    }))
  }
}

#[doc(hidden)]
pub struct SecureDomainsService<S> {
  service: S,
  secure_domains: Vec<String>,
}

impl<S> SecureDomainsService<S> {
  fn check_domain(&self, domain: Option<String>) -> bool {
    if self.secure_domains.is_empty() {
      return true;
    }
    let domain = match domain {
      Some(d) if !d.is_empty() => d,
      _ => return true,
    };
    if let Ok(url) = Url::parse(&domain) {
      if let Some(host) = url.host_str() {
        return self.secure_domains.contains(&host.to_string());
      }
    }
    let host = domain.split(':').next().unwrap_or(&domain);
    self.secure_domains.contains(&host.to_string())
  }
}

impl<S, B> Service<ServiceRequest> for SecureDomainsService<S>
where
  S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
  S::Future: 'static,
  B: 'static,
{
  type Response = ServiceResponse<EitherBody<B>>;
  type Error = Error;
  type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

  forward_ready!(service);

  fn call(&self, req: ServiceRequest) -> Self::Future {
    let path = req.path();

    if path.starts_with("/api/") || path.starts_with("/ui/profile") {
      return self
        .service
        .call(req)
        .map_ok(ServiceResponse::map_into_left_body)
        .boxed_local();
    }

    let checking = extract_referer(req.request()).or_else(|| {
      let origin = extract_origin(req.request());
      if origin.is_empty() {
        None
      } else {
        Some(origin)
      }
    });

    let is_exact_ui_root = path == "/ui" || path == "/ui/";

    // 1. If headers are missing
    if checking.is_none() {
      // Allow ONLY if it's exact /ui or /ui/
      if is_exact_ui_root {
        return self
          .service
          .call(req)
          .map_ok(ServiceResponse::map_into_left_body)
          .boxed_local();
      } else {
        // Deny all other paths if no referrer/origin provided
        return Box::pin(async {
          Ok(req.into_response(HttpResponse::Forbidden().finish().map_into_right_body()))
        });
      }
    }

    // 2. If headers exist, must pass domain check
    if !self.check_domain(checking) {
      return Box::pin(async {
        Ok(req.into_response(HttpResponse::Forbidden().finish().map_into_right_body()))
      });
    }

    self
      .service
      .call(req)
      .map_ok(ServiceResponse::map_into_left_body)
      .boxed_local()
  }
}
